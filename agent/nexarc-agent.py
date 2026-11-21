#!/usr/bin/env python3
"""Agent de supervision NEXARC.

Posé sur un poste, il remonte son état (CPU/RAM/disque, posture, inventaire,
logiciels, mises à jour) et relève ses tâches. Durci par rapport à la 1.x :

  - TLS TOUJOURS vérifié : autorité (système, ou fichier NEXARC_CA), ou
    empreinte SHA-256 épinglée (NEXARC_PIN). La vérification par autorité ne
    cède la place qu'à une empreinte bien formée, jamais à rien.
  - La posture remontée est constatée, jamais supposée : antivirus, pare-feu et
    chiffrement sont lus sur le poste ; ce qui ne peut pas l'être part
    « inconnu », et le serveur n'en tire aucune alerte.
  - Le jeton est PROPRE à cet agent : obtenu à l'inscription contre un code à
    usage unique, rangé avec l'URL dans un fichier 0600. Il ne traîne ni dans
    la table des processus, ni dans un fichier d'unité.
  - Aucun shell=True : chaque commande est un binaire fixe avec ses arguments en
    liste ; les types de tâches sont une liste fermée, identique au serveur ;
    les noms de paquets sont validés ; délais et tailles de sortie bornés.

Installation : le script d'inscription lance « --enroller » (échange du code,
écriture du jeton en 0600, pose du service). Ensuite le service lance l'agent
sans argument : il lit sa configuration et remonte.
"""
import argparse
import base64
import glob
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse

IS_WIN = sys.platform.startswith('win')
IS_MAC = sys.platform == 'darwin'
IS_LINUX = not IS_WIN and not IS_MAC

try:
    import psutil
except ImportError:
    sys.exit('psutil requis :  pip install psutil requests')
try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    sys.exit('requests requis :  pip install psutil requests')

VERSION = '2.7.0'
KINDS = {'cmd', 'install', 'uninstall', 'inventory', 'update', 'wol', 'eteindre', 'redemarrer', 'reveil-prep', 'preparer-ecran', 'agent-maj'}
PAQUET = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._+:@/-]{0,120}$')
SORTIE_MAX = 100_000
# Un jeton refusé (révoqué, machine supprimée) ne redevient pas bon en
# insistant : l'agent se tait plus d'une heure, le temps que le serveur oublie
# ses échecs, et ne bloque pas l'adresse qu'il partage avec d'autres postes.
ATTENTE_JETON_REFUSE = 65 * 60
FP_SHA256 = re.compile(r'^[0-9a-f]{64}$')
# Sorties des outils de posture en anglais : elles sont analysées, pas affichées.
ENV_C = dict(os.environ, LC_ALL='C', LANG='C')
CONFIG_DIR = (os.path.join(os.environ.get('ProgramData', r'C:\ProgramData'), 'NexarcAgent') if IS_WIN
              else '/usr/local/nexarc-agent' if IS_MAC else '/opt/nexarc-agent')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'agent.json')
JOURNAL_FICHIER = os.path.join(CONFIG_DIR, 'agent.log')
JOURNAL_MAX = 1_000_000


def journal(*parts):
    """Une ligne du service. Sous Linux, systemd la range (journalctl -u
    nexarc-agent) ; sous Windows et macOS, où aucun service ne garde la sortie,
    elle va aussi dans agent.log, à côté de la configuration et fermé comme
    elle : 1 Mo, plus une génération."""
    ligne = ' '.join(str(x) for x in parts)
    print(ligne, flush=True)
    if IS_LINUX:
        return
    try:
        if os.path.exists(JOURNAL_FICHIER) and os.path.getsize(JOURNAL_FICHIER) > JOURNAL_MAX:
            os.replace(JOURNAL_FICHIER, JOURNAL_FICHIER + '.1')
        with open(JOURNAL_FICHIER, 'a', encoding='utf-8') as f:
            f.write(time.strftime('%Y-%m-%d %H:%M:%S ') + ligne + '\n')
    except OSError:
        pass  # un journal plein ou illisible n'arrête jamais l'agent


def normaliser_empreinte(texte):
    """'sha256:AA:BB…' → 'aabb…' (64 hexa), ou ValueError : une empreinte mal
    formée ne doit jamais aboutir à une session sans vérification."""
    brut = re.sub(r'^\s*sha-?256\s*[:=]?\s*', '', str(texte or ''), flags=re.I)
    fp = re.sub(r'[^0-9a-fA-F]', '', brut).lower()
    if not FP_SHA256.match(fp):
        raise ValueError('empreinte SHA-256 invalide (64 caractères hexadécimaux attendus)')
    return fp


class EpingleAdapter(HTTPAdapter):
    """Exige que le certificat présenté ait exactement l'empreinte SHA-256
    épinglée (serveur au certificat auto-signé, confiance au premier usage).
    Sans correspondance, la connexion échoue avant le moindre octet envoyé."""

    def __init__(self, empreinte, **kw):
        self._fp = normaliser_empreinte(empreinte)
        super().__init__(**kw)

    def init_poolmanager(self, *a, **kw):
        kw['assert_fingerprint'] = self._fp
        super().init_poolmanager(*a, **kw)


class SessionAgent(requests.Session):
    """requests laisse REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE, s'ils existent dans
    l'environnement, remplacer session.verify à chaque requête : une empreinte
    épinglée ou un NEXARC_CA seraient alors ignorés sans bruit. Ici le choix
    configuré l'emporte ; seul le chemin « autorités du système » accepte le
    lot désigné par l'environnement (c'est encore une vérification par autorité)."""

    def merge_environment_settings(self, url, proxies, stream, verify, cert):
        reglages = super().merge_environment_settings(url, proxies, stream, verify, cert)
        if verify is None and self.verify is not True:
            reglages['verify'] = self.verify
        return reglages


def session_http(url, pin=None, ca=None):
    """Deux chemins, et seulement deux :
      - empreinte épinglée : la vérification par autorité est remplacée par la
        comparaison de l'empreinte (urllib3 n'accepte assert_fingerprint
        qu'avec verify=False) — ce n'est pas une vérification en moins, c'est
        une vérification plus stricte : un seul certificat passe ;
      - sinon : vérification par autorité, toujours — le fichier NEXARC_CA
        s'il est donné, les autorités du système autrement."""
    s = SessionAgent()
    if pin:
        s.mount('https://', EpingleAdapter(pin))
        s.verify = False
    else:
        s.verify = ca if ca else True
    return s


def oskind():
    s = platform.system().lower()
    if s == 'windows':
        return 'win'
    if s == 'darwin':
        return 'mac'
    if s == 'linux':
        try:
            racine = os.geteuid() == 0
        except AttributeError:
            racine = False
        return 'srv' if not os.environ.get('DISPLAY') and racine else 'lin'
    return 'lin'


def os_label():
    s = platform.system()
    if s == 'Windows':
        return 'Windows ' + platform.release()
    if s == 'Darwin':
        return 'macOS ' + platform.mac_ver()[0]
    return '%s %s' % (s, platform.release())


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('192.0.2.1', 1))  # adresse de documentation : ne route pas, révèle l'IP locale
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return socket.gethostbyname(socket.gethostname())


def disk_percent():
    try:
        return int(psutil.disk_usage('C:\\' if IS_WIN else '/').percent)
    except OSError:
        return 0


def run(cmd, timeout=25, env=None):
    """Exécute une commande — binaire fixe, arguments en LISTE, jamais shell=True.
    Renvoie (rc, sortie) et ne lève jamais."""
    try:
        r = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout, errors='replace', env=env)
        return r.returncode, ((r.stdout or '') + (r.stderr or ''))[:SORTIE_MAX]
    except subprocess.TimeoutExpired:
        return 124, '[délai dépassé]'
    except (OSError, ValueError) as e:
        return 1, str(e)


# Chaque lecteur rend un état du vocabulaire que le serveur connaît, ou
# « inconnu » quand l'outil manque ou répond de travers. Les analyseurs sont
# des fonctions pures, essayées sur des sorties réelles dans test_agent.py.
POWERSHELL = ['powershell', '-NoProfile', '-NonInteractive', '-Command']


def av_securitycenter(etats):
    """productState des antivirus que Windows déclare (SecurityCenter2) : bit
    0x1000 = moteur actif, bit 0x10 = signatures périmées."""
    if not etats:
        return 'absent'
    actifs = [e for e in etats if (e >> 12) & 0x1]
    if not actifs:
        return 'inactif'
    return 'à jour' if any(not (e & 0x10) for e in actifs) else 'obsolète'


def av_defender(etat):
    """Get-MpComputerStatus (Windows Server, sans centre de sécurité)."""
    if not etat.get('AntivirusEnabled') or not etat.get('RealTimeProtectionEnabled'):
        return 'inactif'
    age = etat.get('AntivirusSignatureAge')
    return 'obsolète' if isinstance(age, int) and age > 7 else 'à jour'


def antivirus_state():
    try:
        if IS_WIN:
            rc, out = run(POWERSHELL + ['(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct '
                                        '-ErrorAction Stop | ForEach-Object { $_.productState }) -join ","'], 30)
            if rc == 0:
                return av_securitycenter([int(x) for x in out.strip().split(',') if x.strip().isdigit()])
            rc, out = run(POWERSHELL + ['Get-MpComputerStatus -ErrorAction Stop | Select-Object AntivirusEnabled,'
                                        'RealTimeProtectionEnabled,AntivirusSignatureAge | ConvertTo-Json'], 30)
            return av_defender(json.loads(out)) if rc == 0 else 'inconnu'
        if IS_MAC:
            # XProtect fait partie du système et ne se désactive pas.
            for chemin in ('/Library/Apple/System/Library/CoreServices/XProtect.bundle',
                           '/System/Library/CoreServices/XProtect.bundle'):
                if os.path.isdir(chemin):
                    return 'actif'
            return 'inconnu'
        # Linux : ClamAV est le seul moteur reconnu ; son absence est dite telle.
        rc, out = run(['systemctl', 'is-active', 'clamav-daemon', 'clamd@scan'], 8, env=ENV_C)
        if 'active' in out.split():
            return 'actif'
        return 'inactif' if (shutil.which('clamscan') or shutil.which('clamdscan')) else 'absent'
    except (OSError, ValueError):
        return 'inconnu'


def pare_feu_windows(sortie):
    """(Get-NetFirewallProfile).Enabled joint par des virgules : 'True,True,True'."""
    vals = [v.strip().lower() for v in sortie.strip().split(',') if v.strip()]
    if not vals or any(v not in ('true', 'false') for v in vals):
        return 'inconnu'
    return 'actif' if all(v == 'true' for v in vals) else 'inactif'


def pare_feu_macos(sortie):
    s = sortie.lower()
    if re.search(r'state = [12]\b', s) or 'is enabled' in s:
        return 'actif'
    if 'state = 0' in s or 'is disabled' in s:
        return 'inactif'
    return 'inconnu'


def nft_filtre_entree(sortie):
    """Vrai si une chaîne accrochée à l'entrée filtre quelque chose : politique
    drop, ou au moins une règle."""
    for bloc in re.findall(r'chain [^{]+\{(.*?)\n\s*\}', sortie, re.S):
        if 'hook input' not in bloc:
            continue
        if 'policy drop' in bloc:
            return True
        regles = [l.strip() for l in bloc.splitlines() if l.strip() and not l.strip().startswith('type ')]
        if regles:
            return True
    return False


def iptables_filtre_entree(sortie):
    return bool(re.search(r'^-P INPUT (DROP|REJECT)', sortie, re.M) or re.search(r'^-A INPUT ', sortie, re.M))


def firewall_state():
    try:
        if IS_WIN:
            rc, out = run(POWERSHELL + ['(Get-NetFirewallProfile -ErrorAction Stop).Enabled -join ","'], 30)
            return pare_feu_windows(out) if rc == 0 else 'inconnu'
        if IS_MAC:
            rc, out = run(['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'], 8, env=ENV_C)
            return pare_feu_macos(out) if rc == 0 else 'inconnu'
        lu = False
        if shutil.which('firewall-cmd'):
            lu = True
            if run(['firewall-cmd', '--state'], 8, env=ENV_C)[1].strip() == 'running':
                return 'actif'
        if shutil.which('ufw'):
            rc, out = run(['ufw', 'status'], 8, env=ENV_C)
            if rc == 0:
                lu = True
                if re.search(r'^Status:\s*active', out, re.M):
                    return 'actif'
        if shutil.which('nft'):
            rc, out = run(['nft', 'list', 'ruleset'], 8, env=ENV_C)
            if rc == 0:
                lu = True
                if nft_filtre_entree(out):
                    return 'actif'
        if shutil.which('iptables'):
            rc, out = run(['iptables', '-S', 'INPUT'], 8, env=ENV_C)
            if rc == 0:
                lu = True
                if iptables_filtre_entree(out):
                    return 'actif'
        return 'inactif' if lu else 'inconnu'
    except (OSError, ValueError):
        return 'inconnu'


def encryption_state():
    try:
        if IS_WIN:
            # ProtectionStatus est une énumération (On/Off), pas un texte traduit.
            rc, out = run(POWERSHELL + ['(Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop).ProtectionStatus'], 30)
            if rc != 0:
                return 'inconnu'
            return 'BitLocker actif' if out.strip() == 'On' else 'non chiffré'
        if IS_MAC:
            rc, out = run(['fdesetup', 'status'], 8, env=ENV_C)
            if rc != 0:
                return 'inconnu'
            return 'FileVault actif' if 'filevault is on' in out.lower() else 'non chiffré'
        rc, out = run(['lsblk', '-n', '-o', 'TYPE'], 8, env=ENV_C)
        if rc != 0:
            return 'inconnu'
        return 'LUKS actif' if 'crypt' in out.split() else 'non chiffré'
    except (OSError, ValueError):
        return 'inconnu'


# Nombre de mises à jour en attente au dernier constat : la liste complète
# n'est relevée qu'un rapport sur douze, le compte part à chaque rapport.
_MAJ_EN_ATTENTE = [0]


def collect(site, name='', relais=False):
    p = {
        # Le nom d'hôte réel : le nom donné à l'inscription est déjà connu de la console.
        'hostname': socket.gethostname()[:80],
        'ip': local_ip(), 'os': os_label(), 'oskind': oskind(),
        'role': 'relais' if relais else 'poste', 'site': site,
        'cpu': int(psutil.cpu_percent(interval=1)), 'ram': int(psutil.virtual_memory().percent),
        'disk': disk_percent(), 'av': antivirus_state(), 'fw': firewall_state(), 'enc': encryption_state(),
        'patch': min(_MAJ_EN_ATTENTE[0], 999),
    }
    return p


def collect_inventory():
    inv = {
        'hostname': socket.gethostname(), 'os': os_label(), 'arch': platform.machine(),
        'kernel': platform.release(), 'cpu_cores': psutil.cpu_count(logical=False) or psutil.cpu_count() or 0,
        'cpu_threads': psutil.cpu_count() or 0, 'ram_total_gb': round(psutil.virtual_memory().total / 1024 ** 3, 1),
        'cpu_model': platform.processor() or '',
    }
    try:
        if IS_LINUX:
            with open('/proc/cpuinfo') as f:
                for line in f:
                    if line.lower().startswith('model name'):
                        inv['cpu_model'] = line.split(':', 1)[1].strip()
                        break
            for cle, chemin in (('vendor', 'sys_vendor'), ('model', 'product_name'), ('serial', 'product_serial')):
                try:
                    with open('/sys/class/dmi/id/' + chemin) as f:
                        inv[cle] = f.read().strip()
                except OSError:
                    pass  # champ DMI illisible sans droits ou absent en VM : laissé vide
        elif IS_MAC:
            rc, out = run(['sysctl', '-n', 'machdep.cpu.brand_string'])
            if rc == 0:
                inv['cpu_model'] = out.strip()
            rc, out = run(['sysctl', '-n', 'hw.model'])
            if rc == 0:
                inv['model'] = out.strip()
            inv['vendor'] = 'Apple'
        elif IS_WIN:
            rc, out = run(['powershell', '-NoProfile', '-Command',
                           '$c=Get-CimInstance Win32_ComputerSystem;$b=Get-CimInstance Win32_BIOS;'
                           '"$($c.Manufacturer)|$($c.Model)|$($b.SerialNumber)"'])
            if rc == 0 and '|' in out:
                v, m, s = (out.strip().split('|') + ['', '', ''])[:3]
                inv['vendor'], inv['model'], inv['serial'] = v, m, s
    except Exception:  # noqa: BLE001 — inventaire au mieux
        pass

    disks = []
    for part in psutil.disk_partitions(all=False):
        try:
            u = psutil.disk_usage(part.mountpoint)
            disks.append({'device': part.device, 'mount': part.mountpoint, 'fs': part.fstype,
                          'total_gb': round(u.total / 1024 ** 3, 1), 'used_pct': int(u.percent)})
        except OSError:
            continue
    inv['disks'] = disks[:12]
    nics = []
    try:
        for nom, items in psutil.net_if_addrs().items():
            ip4 = next((a.address for a in items if a.family == socket.AF_INET), '')
            mac = next((a.address for a in items if getattr(a, 'family', None) == getattr(psutil, 'AF_LINK', -1)), '')
            if ip4 and not ip4.startswith('127.'):
                nics.append({'name': nom, 'ip': ip4, 'mac': mac})
    except (OSError, AttributeError):
        pass  # interfaces illisibles (droits, plateforme) : l'inventaire part sans elles
    inv['nics'] = nics[:8]
    return inv


def collect_software():
    apps = []
    try:
        if IS_WIN:
            import winreg
            racines = [(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'),
                       (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'),
                       (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')]
            vus = set()
            for hive, chemin in racines:
                try:
                    key = winreg.OpenKey(hive, chemin)
                except OSError:
                    continue
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                        nom = winreg.QueryValueEx(sub, 'DisplayName')[0]
                        if not nom or nom in vus:
                            continue
                        vus.add(nom)

                        def val(k):
                            try:
                                return str(winreg.QueryValueEx(sub, k)[0])
                            except OSError:
                                return ''
                        apps.append({'name': nom, 'version': val('DisplayVersion'), 'publisher': val('Publisher'), 'source': 'windows'})
                    except OSError:
                        continue
        elif IS_MAC:
            try:
                for nom in os.listdir('/Applications'):
                    if nom.endswith('.app'):
                        apps.append({'name': nom[:-4], 'version': '', 'publisher': '', 'source': 'app'})
            except OSError:
                pass  # /Applications illisible : la liste reste celle de Homebrew
            rc, out = run(['brew', 'list', '--versions'], 25)
            if rc == 0:
                for line in out.splitlines():
                    p = line.split()
                    if p:
                        apps.append({'name': p[0], 'version': p[1] if len(p) > 1 else '', 'publisher': '', 'source': 'brew'})
        else:
            rc, out = run(['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Maintainer}\n'], 25)
            if rc == 0 and out.strip():
                for line in out.splitlines():
                    p = line.split('\t')
                    if p and p[0]:
                        apps.append({'name': p[0], 'version': p[1] if len(p) > 1 else '', 'publisher': (p[2] if len(p) > 2 else '')[:60], 'source': 'dpkg'})
            else:
                rc, out = run(['rpm', '-qa', '--qf', '%{NAME}\t%{VERSION}\n'], 25)
                if rc == 0:
                    for line in out.splitlines():
                        p = line.split('\t')
                        if p and p[0]:
                            apps.append({'name': p[0], 'version': p[1] if len(p) > 1 else '', 'publisher': '', 'source': 'rpm'})
    except Exception as e:  # noqa: BLE001 — un registre ou un gestionnaire en panne ne doit pas taire le reste
        journal('[nexarc-agent] inventaire logiciel partiel :', e)
    apps.sort(key=lambda a: a['name'].lower())
    return apps[:3000]


def collect_updates():
    ups = []
    try:
        if IS_WIN:
            try:
                rc, out = run([winget(), 'upgrade', '--include-unknown', '--accept-source-agreements'], 90)
            except Indisponible:
                rc, out = 1, ''
            if rc == 0:
                for line in out.splitlines():
                    parts = [c for c in line.split('  ') if c.strip()]
                    if len(parts) >= 4 and not line.lower().startswith(('name', '---')):
                        ups.append({'name': parts[0].strip(), 'current': parts[2].strip(), 'available': parts[3].strip(), 'security': False, 'kind': 'Application'})
            ps = ('$s=New-Object -ComObject Microsoft.Update.Session;$r=$s.CreateUpdateSearcher().Search("IsInstalled=0");'
                  '$r.Updates | ForEach-Object { $_.Title + "|" + (($_.Categories | ForEach-Object {$_.Name}) -join ",") }')
            rc, out = run(['powershell', '-NoProfile', '-Command', ps], 120)
            if rc == 0:
                for line in out.splitlines():
                    if '|' in line:
                        titre, cats = line.split('|', 1)
                        ups.append({'name': titre.strip(), 'current': '', 'available': '', 'security': 'security' in cats.lower(), 'kind': 'Système'})
        elif IS_MAC:
            rc, out = run(['softwareupdate', '-l'], 120)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith('* Label:'):
                    ups.append({'name': line.split(':', 1)[1].strip(), 'current': '', 'available': '', 'security': True, 'kind': 'Système'})
        elif shutil.which('dnf'):
            rc, out = run(['dnf', '-q', 'check-update'], 120)
            if rc == 100:  # 100 : des mises à jour attendent
                for line in out.splitlines():
                    p = line.split()
                    if len(p) == 3 and '.' in p[0]:
                        ups.append({'name': p[0].rsplit('.', 1)[0], 'current': '', 'available': p[1], 'security': False, 'kind': 'Système'})
        elif shutil.which('apt-get'):
            run(['apt-get', 'update', '-qq'], 120, env=ENV_PAQUETS)
            rc, out = run(['apt-get', '-s', 'upgrade'], 60)
            if rc == 0:
                for line in out.splitlines():
                    if line.startswith('Inst '):
                        p = line.split()
                        nom = p[1] if len(p) > 1 else ''
                        secu = 'security' in line.lower()
                        ups.append({'name': nom, 'current': '', 'available': (p[2].strip('()') if len(p) > 2 else ''), 'security': secu, 'kind': 'Système'})
    except Exception as e:  # noqa: BLE001 — une source en panne ne doit pas taire les autres
        journal('[nexarc-agent] mises à jour partielles :', e)
    _MAJ_EN_ATTENTE[0] = len(ups)
    return ups[:600]


class Indisponible(Exception):
    """Le gestionnaire de paquets du poste est introuvable : la tâche échoue avec ce message."""


def winget():
    """winget est une application installée par utilisateur : le compte SYSTEM,
    sous lequel tourne l'agent, ne l'a pas dans son PATH. Son exécutable vit
    dans WindowsApps, un dossier par version : la plus récente."""
    trouve = shutil.which('winget')
    if trouve:
        return trouve
    racine = os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), 'WindowsApps')
    candidats = glob.glob(os.path.join(racine, 'Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe', 'winget.exe'))

    def version(chemin):
        m = re.search(r'DesktopAppInstaller_([0-9.]+)_', chemin)
        return tuple(int(x) for x in m.group(1).split('.')) if m else ()
    if not candidats:
        raise Indisponible('winget introuvable sur ce poste (App Installer absent).')
    return max(candidats, key=version)


def brew():
    """Homebrew refuse de tourner en root, et le PATH d'un LaunchDaemon ne
    l'inclut pas : son chemin complet, lancé au nom du propriétaire de son
    installation."""
    import pwd
    for chemin in (shutil.which('brew'), '/opt/homebrew/bin/brew', '/usr/local/bin/brew'):
        if chemin and os.path.exists(chemin):
            proprietaire = pwd.getpwuid(os.stat(chemin).st_uid).pw_name
            if os.geteuid() == 0 and proprietaire != 'root':
                return ['/usr/bin/sudo', '-u', proprietaire, '-H', '--', chemin]
            return [chemin]
    raise Indisponible('Homebrew introuvable sur ce Mac.')


# Linux : le premier gestionnaire présent ; les commandes sont non interactives.
GESTIONNAIRES = {
    'apt-get': {'install': ['apt-get', 'install', '-y', '-q'], 'uninstall': ['apt-get', 'remove', '-y', '-q'],
                'update': ['apt-get', 'install', '-y', '-q', '--only-upgrade'], 'tout': ['apt-get', 'upgrade', '-y', '-q'],
                'avant': ['apt-get', 'update', '-qq']},
    'dnf': {'install': ['dnf', 'install', '-y', '-q'], 'uninstall': ['dnf', 'remove', '-y', '-q'],
            'update': ['dnf', 'upgrade', '-y', '-q'], 'tout': ['dnf', 'upgrade', '-y', '-q']},
    'zypper': {'install': ['zypper', '--non-interactive', 'install'], 'uninstall': ['zypper', '--non-interactive', 'remove'],
               'update': ['zypper', '--non-interactive', 'update'], 'tout': ['zypper', '--non-interactive', 'update']},
    'pacman': {'install': ['pacman', '-S', '--noconfirm', '--needed'], 'uninstall': ['pacman', '-R', '--noconfirm'],
               'update': ['pacman', '-S', '--noconfirm'], 'tout': ['pacman', '-Syu', '--noconfirm']},
}
# apt sans question (fichiers de configuration, services à redémarrer).
ENV_PAQUETS = dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='a')


def gestionnaire_linux():
    for nom, cmds in GESTIONNAIRES.items():
        if shutil.which(nom):
            return cmds
    raise Indisponible('aucun gestionnaire de paquets reconnu (apt, dnf, zypper, pacman).')


def pkg_cmd(kind, paquet):
    """Commande gestionnaire de paquets — arguments en liste, paquet validé.
    None : nom de paquet refusé ; Indisponible : pas de gestionnaire."""
    if not PAQUET.match(paquet):
        return None
    if IS_WIN:
        if kind == 'install':
            return [winget(), 'install', '-e', '--id', paquet, '--silent', '--accept-source-agreements', '--accept-package-agreements']
        return [winget(), 'uninstall', '-e', '--id', paquet, '--silent', '--accept-source-agreements']
    if IS_MAC:
        return brew() + ['install' if kind == 'install' else 'uninstall', paquet]
    return gestionnaire_linux()[kind] + [paquet]


def maj_cmd(paquet):
    if paquet and not PAQUET.match(paquet):
        return None
    if IS_WIN:
        return [winget(), 'upgrade', '-e', '--id', paquet, '--silent', '--accept-source-agreements', '--accept-package-agreements'] if paquet \
            else [winget(), 'upgrade', '--all', '--silent', '--accept-source-agreements', '--accept-package-agreements']
    if IS_MAC:
        return brew() + ['upgrade', paquet] if paquet else ['softwareupdate', '-i', '-a']
    g = gestionnaire_linux()
    return g['update'] + [paquet] if paquet else g['tout']


def paquets(cmd, timeout):
    """Une commande de paquets : sous apt, les listes rafraîchies d'abord."""
    if IS_LINUX:
        avant = gestionnaire_linux().get('avant')
        if avant:
            run(avant, timeout, env=ENV_PAQUETS)
        return run(cmd, timeout, env=ENV_PAQUETS)
    return run(cmd, timeout)


def shell_fixe(commande):
    """Commande libre : un shell FIXE avec la commande en unique argument (jamais
    shell=True, jamais de chaîne construite). Réservée côté serveur au rôle admin
    sous renfort."""
    return ['cmd.exe', '/c', commande] if IS_WIN else ['/bin/sh', '-c', commande]


def run_job(job, timeout, ctx=None):
    """ctx : ce que certaines tâches demandent de l'agent en marche (session
    vers la console, écran, canal) ; absent, elles répondent qu'il manque."""
    kind, payload = job.get('kind'), (job.get('payload') or '')
    if kind not in KINDS:
        return 1, 'type de tâche inconnu : %s' % kind
    if kind == 'inventory':
        return 0, 'inventaire régénéré'
    if kind == 'wol':
        return wol_send(payload)
    if kind in ('eteindre', 'redemarrer'):
        plus_tard(5, cmd_alimentation(kind))
        return 0, ('arrêt' if kind == 'eteindre' else 'redémarrage') + ' dans 5 secondes'
    if kind == 'reveil-prep':
        return preparer_reveil()
    if kind == 'preparer-ecran':
        if not ctx or not ctx.get('ecran'):
            return 1, 'écran indisponible pour cet agent'
        rc, out = ctx['ecran'].preparer()
        if ctx.get('canal'):
            ctx['canal'].bonjour_si_change()
        return rc, out
    if kind == 'agent-maj':
        if not ctx:
            return 1, 'mise à jour impossible hors du service'
        return mettre_a_jour(ctx['sess'], ctx['base'], ctx['headers'], payload.strip())
    try:
        if kind == 'update':
            cmd = maj_cmd(payload.strip())
            return (1, 'nom de paquet refusé') if cmd is None else paquets(cmd, timeout)
        if kind in ('install', 'uninstall'):
            cmd = pkg_cmd(kind, payload.strip())
            return (1, 'nom de paquet refusé') if cmd is None else paquets(cmd, timeout)
    except Indisponible as e:
        return 1, str(e)
    if kind == 'cmd':
        return run(shell_fixe(payload), timeout)
    return 1, 'type de tâche inconnu'


def wol_send(payload):
    mac = payload.split('|', 1)[0]
    bcast = payload.split('|', 1)[1] if '|' in payload else ''
    clean = mac.replace(':', '').replace('-', '').strip()
    if len(clean) != 12 or not re.match(r'^[0-9a-fA-F]{12}$', clean):
        return 1, 'adresse MAC invalide'
    if bcast and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', bcast):
        bcast = ''
    cibles = ['255.255.255.255'] + ([bcast] if bcast else [])
    try:
        pkt = b'\xff' * 6 + bytes.fromhex(clean) * 16
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            for dst in cibles:
                for port in (9, 7):
                    try:
                        s.sendto(pkt, (dst, port))
                    except OSError:
                        continue
        return 0, 'paquet magique émis vers %s (%s)' % (mac, ', '.join(cibles))
    except OSError as e:
        return 1, 'échec WoL : %s' % e


# ---------------------------------------------------------------------------
# Gestes sur le système : arrêter, redémarrer, préparer le réveil par le
# réseau. Le résultat part d'abord : l'arrêt suit, quelques secondes après.
# ---------------------------------------------------------------------------

def plus_tard(delai, cmd):
    t = threading.Timer(delai, lambda: run(cmd, 60))
    t.daemon = False
    t.start()


def cmd_alimentation(kind):
    if IS_WIN:
        return ['shutdown', '/s' if kind == 'eteindre' else '/r', '/f', '/t', '0']
    if IS_MAC:
        return ['shutdown', '-h' if kind == 'eteindre' else '-r', 'now']
    if shutil.which('systemctl'):
        return ['systemctl', 'poweroff' if kind == 'eteindre' else 'reboot']
    return ['shutdown', '-h' if kind == 'eteindre' else '-r', 'now']


def interfaces_filaires():
    """Les cartes Ethernet physiques (ni Wi-Fi, ni pont, ni interface virtuelle)."""
    noms = []
    for chemin in sorted(glob.glob('/sys/class/net/*')):
        nom = os.path.basename(chemin)
        if nom == 'lo' or not os.path.exists(os.path.join(chemin, 'device')) or os.path.exists(os.path.join(chemin, 'wireless')):
            continue
        noms.append(nom)
    return noms


def preparer_reveil():
    """Le réveil par le réseau (paquet magique) activé sur ce que le système
    règle ; le BIOS/UEFI, lui, reste à vérifier à la main."""
    lignes = []
    if IS_MAC:
        rc, out = run(['pmset', '-a', 'womp', '1'], 30)
        lignes.append('réveil par le réseau (womp) activé' if rc == 0 else 'pmset : %s' % out.strip()[:200])
        return rc, '\n'.join(lignes)
    if IS_WIN:
        ps = ("$r=@(); Get-NetAdapter -Physical | Where-Object { $_.MediaType -eq '802.3' } | ForEach-Object { "
              "try { Set-NetAdapterPowerManagement -Name $_.Name -WakeOnMagicPacket Enabled -ErrorAction Stop; $r+=($_.Name+' : paquet magique active') } "
              "catch { $r+=($_.Name+' : '+$_.Exception.Message) }; "
              "Set-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword '*WakeOnMagicPacket' -RegistryValue 1 -ErrorAction SilentlyContinue }; "
              "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' -Name HiberbootEnabled -Value 0 -Type DWord; "
              "$r+='demarrage rapide desactive (une machine eteinte reste joignable)'; $r -join [Environment]::NewLine")
        rc, out = run(POWERSHELL + [ps], 90)
        return rc, out.strip() + '\nVérifie aussi le BIOS/UEFI : « Wake on LAN » doit y être activé.'
    if not shutil.which('ethtool'):
        try:
            cmd = pkg_cmd('install', 'ethtool')
            if cmd:
                paquets(cmd, 300)
        except Indisponible:
            pass
    ethtool = shutil.which('ethtool')
    if not ethtool:
        return 1, 'ethtool introuvable et non installable : réveil par le réseau non réglé.'
    reglees = []
    for nom in interfaces_filaires():
        rc, out = run([ethtool, nom], 15)
        m = re.search(r'Supports Wake-on:\s*(\S+)', out)
        if not m or 'g' not in m.group(1):
            lignes.append('%s : la carte ne sait pas se réveiller par paquet magique' % nom)
            continue
        rc, out = run([ethtool, '-s', nom, 'wol', 'g'], 15)
        if rc != 0:
            lignes.append('%s : %s' % (nom, out.strip()[:200]))
            continue
        reglees.append(nom)
        lignes.append('%s : paquet magique activé' % nom)
        if shutil.which('nmcli'):
            rc, con = run(['nmcli', '-g', 'GENERAL.CONNECTION', 'device', 'show', nom], 15)
            con = con.strip()
            if rc == 0 and con:
                run(['nmcli', 'connection', 'modify', con, '802-3-ethernet.wake-on-lan', 'magic'], 15)
    if reglees and shutil.which('systemctl'):
        # Gardé au démarrage, que le réseau soit géré par NetworkManager ou non.
        unite = '/etc/systemd/system/nexarc-wol.service'
        with open(unite, 'w') as f:
            f.write('[Unit]\nDescription=NEXARC : réveil par le réseau\nAfter=network.target\n\n[Service]\nType=oneshot\n'
                    + ''.join('ExecStart=%s -s %s wol g\n' % (ethtool, n) for n in reglees)
                    + '\n[Install]\nWantedBy=multi-user.target\n')
        run(['systemctl', 'daemon-reload'], 30)
        run(['systemctl', 'enable', 'nexarc-wol.service'], 30)
        lignes.append('réglage gardé au démarrage (nexarc-wol.service)')
    if not lignes:
        return 1, 'aucune carte Ethernet filaire trouvée'
    lignes.append('Vérifie aussi le BIOS/UEFI : « Wake on LAN » doit y être activé.')
    return (0 if reglees else 1), '\n'.join(lignes)


# ---------------------------------------------------------------------------
# Mise à jour de l'agent : le code distribué par la console, vérifié sur son
# empreinte avant de remplacer quoi que ce soit, puis le service relancé.
# ---------------------------------------------------------------------------

def code_actuel():
    with open(os.path.abspath(__file__), 'rb') as f:
        return f.read()


def empreinte_code():
    return hashlib.sha256(code_actuel()).hexdigest()


def redemarrer_plus_tard(delai=5):
    """Relance le service de l'agent depuis un processus détaché du sien : la
    relance survit à l'arrêt de l'agent qui la demande."""
    if IS_WIN:
        relance = ('powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep %d; '
                   'Stop-ScheduledTask -TaskName NexarcAgent; Start-ScheduledTask -TaskName NexarcAgent"' % delai)
        return run(POWERSHELL + ["Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='%s'} | Out-Null" % relance.replace("'", "''")], 60)
    if IS_MAC:
        subprocess.Popen(['/bin/sh', '-c', 'sleep %d; launchctl kickstart -k system/fr.nexarc.agent' % delai],
                         start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return 0, ''
    if shutil.which('systemd-run'):
        return run(['systemd-run', '--on-active=%d' % delai, '--unit=nexarc-agent-relance-%d' % int(time.time()),
                    'systemctl', 'restart', 'nexarc-agent'], 30)
    subprocess.Popen(['/bin/sh', '-c', 'sleep %d; systemctl restart nexarc-agent' % delai],
                     start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return 0, ''


def mettre_a_jour(sess, base, headers, attendu):
    if not FP_SHA256.match(attendu or ''):
        return 1, 'empreinte attendue invalide'
    if attendu == empreinte_code():
        return 0, 'agent déjà à jour'
    try:
        r = sess.get(base + '/api/agent/code', headers=headers, timeout=60)
    except requests.RequestException as e:
        return 1, 'code non téléchargé : %s' % e
    if r.status_code != 200:
        return 1, 'la console a répondu %s' % r.status_code
    if hashlib.sha256(r.content).hexdigest() != attendu:
        return 1, 'empreinte du code reçu différente de celle annoncée : rien n\'est remplacé'
    try:
        compile(r.content, 'nexarc-agent.py', 'exec')
    except SyntaxError as e:
        return 1, 'code reçu illisible : %s' % e
    chemin = os.path.abspath(__file__)
    provisoire = chemin + '.nouveau'
    with open(provisoire, 'wb') as f:
        f.write(r.content)
    os.replace(provisoire, chemin)
    rc, out = redemarrer_plus_tard()
    if rc != 0:
        return 1, 'agent remplacé, relance du service refusée : %s' % out.strip()[:200]
    nouvelle = re.search(rb"^VERSION = '([0-9.]+)'$", r.content, re.M)
    return 0, 'agent remplacé (%s) ; le service redémarre dans quelques secondes' % (nouvelle.group(1).decode() if nouvelle else '?')


# ---------------------------------------------------------------------------
# L'écran : le serveur VNC local, réglé par l'agent et joint par lui seul
# (boucle locale). Le pont de la console s'authentifie avec le mot de passe
# que l'agent a choisi ; il ne quitte jamais le canal chiffré.
# ---------------------------------------------------------------------------

KICKSTART = '/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart'
ALPHANUM = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'


def port_libre():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def joignable(port, delai=1.0):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=delai):
            return True
    except OSError:
        return False


def types_securite(port):
    """Les types de sécurité qu'offre le serveur VNC local (RFB 3.8)."""
    with socket.create_connection(('127.0.0.1', port), timeout=4) as s:
        f = s.makefile('rb')
        if not f.read(12).startswith(b'RFB '):
            return []
        s.sendall(b'RFB 003.008\n')
        n = f.read(1)
        return list(f.read(n[0])) if n else []


def session_graphique_linux():
    """(type, affichage) de la session active du poste : x11, wayland, tty ou ''."""
    typ, aff = '', ''
    if shutil.which('loginctl'):
        rc, out = run(['loginctl', 'show-seat', 'seat0', '-p', 'ActiveSession'], 5)
        sid = out.strip().partition('=')[2] if rc == 0 else ''
        if sid:
            rc, out = run(['loginctl', 'show-session', sid, '-p', 'Type', '-p', 'Display'], 5)
            for ligne in out.splitlines():
                cle, _, val = ligne.partition('=')
                if cle == 'Type':
                    typ = val.strip()
                elif cle == 'Display':
                    aff = val.strip()
    if not aff:
        nums = sorted(int(m.group(1)) for m in (re.match(r'X(\d+)$', os.path.basename(p)) for p in glob.glob('/tmp/.X11-unix/X*')) if m)
        if nums:
            aff = ':%d' % nums[0]
    return typ, aff


def auth_x(aff):
    """Le fichier d'autorisation que le serveur X de cet affichage a reçu
    (« -auth » de sa ligne de commande : GDM, LightDM, startx), ou None."""
    for p in psutil.process_iter(['name', 'cmdline']):
        try:
            nom, args = p.info['name'] or '', p.info['cmdline'] or []
        except (psutil.Error, KeyError):
            continue
        if not re.match(r'^(Xorg|X|Xvfb|Xwayland|Xvnc|Xtigervnc)$', os.path.basename(nom)):
            continue
        sien = aff in args or (aff == ':0' and not any(re.match(r'^:\d+$', a) for a in args))
        if sien and '-auth' in args and args.index('-auth') + 1 < len(args):
            return args[args.index('-auth') + 1]
    return None


def conf_gdm():
    for p in ('/etc/gdm3/custom.conf', '/etc/gdm/custom.conf', '/etc/gdm3/daemon.conf'):
        if os.path.exists(p):
            return p
    return None


def gdm_en_x11(chemin):
    """WaylandEnable=false dans [daemon] : l'écran de connexion et les sessions
    passent en X11, que x11vnc sait montrer. Pris en compte au prochain démarrage."""
    with open(chemin, encoding='utf-8', errors='replace') as f:
        texte = f.read()
    if re.search(r'^\s*WaylandEnable\s*=\s*false', texte, re.M):
        return False
    if re.search(r'^\s*#?\s*WaylandEnable\s*=.*$', texte, re.M):
        texte = re.sub(r'^\s*#?\s*WaylandEnable\s*=.*$', 'WaylandEnable=false', texte, count=1, flags=re.M)
    elif re.search(r'^\[daemon\]\s*$', texte, re.M):
        texte = re.sub(r'^\[daemon\]\s*$', '[daemon]\nWaylandEnable=false', texte, count=1, flags=re.M)
    else:
        texte += '\n[daemon]\nWaylandEnable=false\n'
    with open(chemin + '.nexarc', 'w', encoding='utf-8') as f:
        f.write(texte)
    os.replace(chemin + '.nexarc', chemin)
    return True


class Ecran:
    def __init__(self, cfg):
        self.cfg = cfg
        self.verrou = threading.Lock()
        self.x11vnc = None        # (processus, affichage, port)
        self.installation = None  # fil de préparation en cours

    def mot_de_passe(self):
        if not self.cfg.get('vnc_mdp'):
            self.cfg['vnc_mdp'] = ''.join(secrets.choice(ALPHANUM) for _ in range(8))
            ecrire_config(self.cfg)
        return self.cfg['vnc_mdp']

    def etat(self):
        """('pret' | 'a-installer' | 'a-activer' | 'indisponible', raison)."""
        if not self.cfg.get('prise_en_main', True):
            return 'indisponible', 'prise en main désactivée sur ce poste (agent.json)'
        if self.installation and self.installation.is_alive():
            return 'a-installer', 'préparation de l\'écran en cours'
        if IS_WIN:
            rc, _ = run(['sc', 'query', 'tvnserver'], 10)
            if rc != 0:
                return 'a-installer', 'TightVNC sera installé et réglé par l\'agent (boucle locale seulement)'
            if not self.cfg.get('vnc_tightvnc'):
                return 'a-installer', 'TightVNC présent : l\'agent le règle (mot de passe, boucle locale)'
            return 'pret', ''
        if IS_MAC:
            if joignable(5900):
                return 'pret', ''
            return 'a-activer', ('Active une fois « Partage d\'écran » : Réglages Système → Général → Partage. '
                                 'macOS ne laisse plus un programme l\'activer à ta place.')
        typ, aff = session_graphique_linux()
        if typ == 'wayland':
            return 'a-activer', ('Session Wayland : « Préparer l\'écran » passe l\'écran de connexion en X11 '
                                 '(pris en compte au prochain démarrage).')
        if not aff:
            return 'indisponible', 'aucun affichage graphique sur ce poste : le terminal reste disponible'
        if not shutil.which('x11vnc'):
            return 'a-installer', 'x11vnc sera installé par l\'agent'
        return 'pret', ''

    def preparer(self):
        """Installe ou règle le serveur VNC local. Renvoie (rc, compte rendu)."""
        if IS_WIN:
            return self._preparer_windows()
        if IS_MAC:
            return self._preparer_mac()
        return self._preparer_linux()

    def preparer_en_fond(self, fin=None):
        with self.verrou:
            if self.installation and self.installation.is_alive():
                return

            def tache():
                rc, out = self.preparer()
                journal('[nexarc-agent] écran préparé (%s) : %s' % (rc, out.strip()[:300]))
                if fin:
                    fin()
            self.installation = threading.Thread(target=tache, daemon=True, name='ecran')
            self.installation.start()

    def _preparer_windows(self):
        mdp = self.mot_de_passe()
        rc, _ = run(['sc', 'query', 'tvnserver'], 10)
        options = ('/quiet /norestart ADDLOCAL=Server SERVER_REGISTER_AS_SERVICE=1 SERVER_ADD_FIREWALL_EXCEPTION=0 '
                   'SET_USEVNCAUTHENTICATION=1 VALUE_OF_USEVNCAUTHENTICATION=1 SET_PASSWORD=1 VALUE_OF_PASSWORD=%s '
                   'SET_LOOPBACKONLY=1 VALUE_OF_LOOPBACKONLY=1 SET_ALLOWLOOPBACK=1 VALUE_OF_ALLOWLOOPBACK=1 '
                   'SET_ACCEPTHTTPCONNECTIONS=1 VALUE_OF_ACCEPTHTTPCONNECTIONS=0' % mdp)
        try:
            cmd = [winget(), 'install', '-e', '--id', 'GlavSoft.TightVNC', '--silent', '--accept-source-agreements',
                   '--accept-package-agreements', '--override', options] + (['--force'] if rc == 0 else [])
        except Indisponible as e:
            return 1, str(e)
        rc, out = run(cmd, 900)
        if rc != 0 and 'already installed' not in out.lower():
            return rc, 'installation de TightVNC : %s' % out.strip()[-400:]
        # Au cas où l'installateur garderait d'anciens réglages : boucle locale
        # seulement, pas de serveur web, puis le service relancé.
        cle = r'HKLM\SOFTWARE\TightVNC\Server'
        for nom, val in (('LoopbackOnly', '1'), ('AllowLoopback', '1'), ('AcceptHttpConnections', '0'), ('UseVncAuthentication', '1')):
            run(['reg', 'add', cle, '/v', nom, '/t', 'REG_DWORD', '/d', val, '/f'], 15)
        run(POWERSHELL + ['Restart-Service -Name tvnserver -Force'], 60)
        self.cfg['vnc_tightvnc'] = True
        ecrire_config(self.cfg)
        return 0, 'TightVNC installé et réglé (boucle locale seulement, mot de passe propre à ce poste)'

    def _preparer_mac(self):
        mdp = self.mot_de_passe()
        if not os.path.exists(KICKSTART):
            return 1, 'kickstart introuvable'
        rc, out = run([KICKSTART, '-activate', '-configure', '-access', '-on', '-privs', '-all', '-allowAccessFor', '-allUsers',
                       '-clientopts', '-setvnclegacy', '-vnclegacy', 'yes', '-setvncpw', '-vncpw', mdp, '-restart', '-agent'], 120)
        self.cfg['vnc_mac'] = rc == 0
        ecrire_config(self.cfg)
        if joignable(5900):
            return 0, 'Partage d\'écran actif.'
        return 1, ('Partage d\'écran pas encore actif : Réglages Système → Général → Partage → Partage d\'écran '
                   '(macOS exige ce geste une fois, sur place).')

    def _preparer_linux(self):
        lignes, rc_final = [], 0
        if not shutil.which('x11vnc'):
            try:
                cmd = pkg_cmd('install', 'x11vnc')
                rc, out = paquets(cmd, 600) if cmd else (1, 'paquet refusé')
            except Indisponible as e:
                rc, out = 1, str(e)
            lignes.append('x11vnc installé' if rc == 0 else 'x11vnc non installé : %s' % out.strip()[-300:])
            rc_final = rc
        typ, _ = session_graphique_linux()
        gdm = conf_gdm()
        if typ == 'wayland' or (gdm and not typ):
            if gdm:
                try:
                    if gdm_en_x11(gdm):
                        lignes.append('écran de connexion passé en X11 (%s) : effectif au prochain démarrage' % gdm)
                except OSError as e:
                    lignes.append('réglage de GDM impossible : %s' % e)
                    rc_final = 1
            else:
                lignes.append('session Wayland hors GDM : choisis une session « Xorg » à la connexion')
        self.mot_de_passe()
        return rc_final, '\n'.join(lignes) or 'écran prêt'

    def _x11vnc(self, aff):
        """Un x11vnc par affichage, lancé à la demande et gardé ensuite."""
        with self.verrou:
            if self.x11vnc and self.x11vnc[0].poll() is None and self.x11vnc[1] == aff:
                return self.x11vnc[2]
            if self.x11vnc and self.x11vnc[0].poll() is None:
                self.x11vnc[0].terminate()
            fichier = os.path.join(CONFIG_DIR, 'vnc.pass')
            rc, out = run(['x11vnc', '-storepasswd', self.mot_de_passe(), fichier], 15)
            if rc != 0:
                raise Indisponible('mot de passe VNC non posé : %s' % out.strip()[:200])
            os.chmod(fichier, 0o600)
            trace = os.path.join(CONFIG_DIR, 'x11vnc.log')
            # L'autorisation du serveur X : celle de sa ligne de commande, sinon
            # aucune (serveur sans contrôle d'accès), sinon la devinette de x11vnc.
            fichier_x = auth_x(aff)
            essais = ([['-auth', fichier_x]] if fichier_x else [[]]) + [['-auth', 'guess']]
            fin = ''
            for auth in essais:
                port = port_libre()
                with open(trace, 'w') as sortie:
                    p = subprocess.Popen(['x11vnc', '-display', aff] + auth + ['-localhost', '-rfbport', str(port),
                                          '-rfbauth', fichier, '-forever', '-shared', '-noxdamage'],
                                         stdin=subprocess.DEVNULL, stdout=sortie, stderr=subprocess.STDOUT)
                for _ in range(60):
                    if p.poll() is not None:
                        break
                    if joignable(port, 0.3):
                        self.x11vnc = (p, aff, port)
                        return port
                    time.sleep(0.25)
                try:
                    p.kill()
                except OSError:
                    pass
                with open(trace, errors='replace') as f:
                    lignes = [l for l in f.read().splitlines() if l.strip() and 'netstat' not in l]
                fin = ' / '.join(lignes[-3:])[-400:]
            raise Indisponible('x11vnc n\'a pas démarré sur %s : %s' % (aff, fin or 'sans message'))

    def ouvrir(self):
        """(socket vers le serveur VNC local, mot de passe à présenter ou None)."""
        etat, raison = self.etat()
        if etat != 'pret':
            if etat == 'a-installer':
                raise Indisponible('Écran en préparation : %s. Réessaie dans une minute.' % raison)
            raise Indisponible(raison)
        if IS_WIN:
            port, mdp = 5900, self.mot_de_passe()
        elif IS_MAC:
            port = 5900
            # Mot de passe VNC seulement s'il a été posé ET que le serveur
            # l'offre ; sinon le navigateur demande le compte du Mac (ARD).
            mdp = self.cfg.get('vnc_mdp') if self.cfg.get('vnc_mac') and 2 in types_securite(5900) else None
        else:
            port, mdp = self._x11vnc(session_graphique_linux()[1]), self.mot_de_passe()
        return socket.create_connection(('127.0.0.1', port), timeout=10), mdp

    def arreter(self):
        if self.x11vnc and self.x11vnc[0].poll() is None:
            self.x11vnc[0].terminate()


# ---------------------------------------------------------------------------
# Le terminal : un pseudo-terminal (Linux, macOS) ou une pseudo-console
# (Windows 10 1809 et plus), au compte de l'agent (root, SYSTEM).
# ---------------------------------------------------------------------------

class TerminalPosix:
    def __init__(self, cols, rows):
        import pty
        try:
            import pwd
            compte = pwd.getpwuid(os.geteuid())
            coquille, maison, nom = compte.pw_shell, compte.pw_dir, compte.pw_name
        except (ImportError, KeyError):
            coquille, maison, nom = '', '/', 'root'
        if not coquille or not os.path.exists(coquille) or coquille.endswith(('nologin', 'false')):
            coquille = next((c for c in ('/bin/zsh' if IS_MAC else '/bin/bash', '/bin/bash', '/bin/sh') if os.path.exists(c)), '/bin/sh')
        env = {'TERM': 'xterm-256color', 'COLORTERM': 'truecolor', 'HOME': maison or '/', 'USER': nom, 'LOGNAME': nom, 'SHELL': coquille,
               'LANG': os.environ.get('LANG') or ('en_US.UTF-8' if IS_MAC else 'C.UTF-8'),
               'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' + (':/opt/homebrew/bin' if IS_MAC else '')}
        pid, fd = pty.fork()
        if pid == 0:
            try:
                os.chdir(maison or '/')
            except OSError:
                pass
            try:
                os.execve(coquille, ['-' + os.path.basename(coquille)], env)
            finally:
                os._exit(127)
        self.pid, self.fd = pid, fd
        self.taille(cols, rows)

    def lire(self):
        try:
            return os.read(self.fd, 65536)
        except OSError:
            return b''

    def ecrire(self, data):
        try:
            while data:
                n = os.write(self.fd, data)
                data = data[n:]
        except OSError:
            pass

    def taille(self, cols, rows):
        import fcntl
        import termios
        try:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
        except OSError:
            pass

    def _recolte(self, delai):
        fin = time.time() + delai
        while time.time() < fin:
            try:
                if os.waitpid(self.pid, os.WNOHANG)[0]:
                    return True
            except ChildProcessError:
                return True
            time.sleep(0.05)
        return False

    def fermer(self):
        import signal
        if not self._recolte(0):
            for sig in (signal.SIGHUP, signal.SIGTERM, signal.SIGKILL):
                try:
                    os.kill(self.pid, sig)
                except OSError:
                    break
                if self._recolte(1.0):
                    break
        try:
            os.close(self.fd)
        except OSError:
            pass


class TerminalWindows:
    """ConPTY par ctypes : la console de PowerShell, ses couleurs et ses
    invites, comme dans un vrai terminal."""

    def __init__(self, cols, rows):
        import ctypes
        from ctypes import wintypes
        self.ct, k = ctypes, ctypes.WinDLL('kernel32', use_last_error=True)
        if not hasattr(k, 'CreatePseudoConsole'):
            raise Indisponible('terminal : Windows 10 1809 ou plus récent requis')
        self.k = k

        class COORD(ctypes.Structure):
            _fields_ = [('X', wintypes.SHORT), ('Y', wintypes.SHORT)]

        class STARTUPINFOW(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('lpReserved', wintypes.LPWSTR), ('lpDesktop', wintypes.LPWSTR), ('lpTitle', wintypes.LPWSTR),
                        ('dwX', wintypes.DWORD), ('dwY', wintypes.DWORD), ('dwXSize', wintypes.DWORD), ('dwYSize', wintypes.DWORD),
                        ('dwXCountChars', wintypes.DWORD), ('dwYCountChars', wintypes.DWORD), ('dwFillAttribute', wintypes.DWORD),
                        ('dwFlags', wintypes.DWORD), ('wShowWindow', wintypes.WORD), ('cbReserved2', wintypes.WORD),
                        ('lpReserved2', ctypes.c_void_p), ('hStdInput', wintypes.HANDLE), ('hStdOutput', wintypes.HANDLE), ('hStdError', wintypes.HANDLE)]

        class STARTUPINFOEXW(ctypes.Structure):
            _fields_ = [('StartupInfo', STARTUPINFOW), ('lpAttributeList', ctypes.c_void_p)]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [('hProcess', wintypes.HANDLE), ('hThread', wintypes.HANDLE), ('dwProcessId', wintypes.DWORD), ('dwThreadId', wintypes.DWORD)]

        self.COORD = COORD
        H = wintypes.HANDLE
        k.CreatePipe.argtypes = [ctypes.POINTER(H), ctypes.POINTER(H), ctypes.c_void_p, wintypes.DWORD]
        k.CreatePseudoConsole.argtypes = [COORD, H, H, wintypes.DWORD, ctypes.POINTER(H)]
        k.CreatePseudoConsole.restype = ctypes.c_long
        k.ResizePseudoConsole.argtypes = [H, COORD]
        k.ResizePseudoConsole.restype = ctypes.c_long
        k.ClosePseudoConsole.argtypes = [H]
        k.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
        k.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
        k.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD,
                                     ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOEXW), ctypes.POINTER(PROCESS_INFORMATION)]
        k.ReadFile.argtypes = [H, ctypes.c_char_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        k.WriteFile.argtypes = [H, ctypes.c_char_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        k.CloseHandle.argtypes = [H]
        k.TerminateProcess.argtypes = [H, wintypes.UINT]

        entree_l, self.entree, self.sortie, sortie_e = H(), H(), H(), H()
        if not k.CreatePipe(ctypes.byref(entree_l), ctypes.byref(self.entree), None, 0) or \
           not k.CreatePipe(ctypes.byref(self.sortie), ctypes.byref(sortie_e), None, 0):
            raise OSError('CreatePipe : %d' % ctypes.get_last_error())
        self.hpc = H()
        hr = k.CreatePseudoConsole(COORD(cols, rows), entree_l, sortie_e, 0, ctypes.byref(self.hpc))
        k.CloseHandle(entree_l)
        k.CloseHandle(sortie_e)
        if hr != 0:
            raise OSError('CreatePseudoConsole : 0x%08x' % (hr & 0xffffffff))
        taille = ctypes.c_size_t()
        k.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(taille))
        self.attributs = (ctypes.c_byte * taille.value)()
        liste = ctypes.cast(self.attributs, ctypes.c_void_p)
        if not k.InitializeProcThreadAttributeList(liste, 1, 0, ctypes.byref(taille)):
            raise OSError('InitializeProcThreadAttributeList : %d' % ctypes.get_last_error())
        # PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE : la valeur est la poignée elle-même.
        if not k.UpdateProcThreadAttribute(liste, 0, 0x00020016, self.hpc, ctypes.sizeof(H), None, None):
            raise OSError('UpdateProcThreadAttribute : %d' % ctypes.get_last_error())
        si = STARTUPINFOEXW()
        si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
        # Sans cela, un processus aux sorties redirigées (un service) les ferait
        # hériter au lieu de la pseudo-console.
        si.StartupInfo.dwFlags = 0x00000100  # STARTF_USESTDHANDLES, poignées nulles
        si.lpAttributeList = liste.value
        pi = PROCESS_INFORMATION()
        racine = os.environ.get('SystemRoot', r'C:\Windows')
        ligne = ctypes.create_unicode_buffer('"%s" -NoLogo' % os.path.join(racine, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'))
        if not k.CreateProcessW(None, ligne, None, None, False, 0x00080000 | 0x00000400, None, racine, ctypes.byref(si), ctypes.byref(pi)):
            raise OSError('CreateProcessW : %d' % ctypes.get_last_error())
        k.CloseHandle(pi.hThread)
        self.processus = pi.hProcess
        self.ferme = False

    def lire(self):
        from ctypes import wintypes
        tampon = self.ct.create_string_buffer(65536)
        lu = wintypes.DWORD()
        if not self.k.ReadFile(self.sortie, tampon, 65536, self.ct.byref(lu), None) or not lu.value:
            return b''
        return tampon.raw[:lu.value]

    def ecrire(self, data):
        from ctypes import wintypes
        ecrit = wintypes.DWORD()
        while data and not self.ferme:
            if not self.k.WriteFile(self.entree, data, len(data), self.ct.byref(ecrit), None):
                return
            data = data[ecrit.value:]

    def taille(self, cols, rows):
        if not self.ferme:
            self.k.ResizePseudoConsole(self.hpc, self.COORD(cols, rows))

    def fermer(self):
        if self.ferme:
            return
        self.ferme = True
        self.k.TerminateProcess(self.processus, 0)
        # ClosePseudoConsole peut attendre que la sortie soit lue : à part.
        threading.Thread(target=lambda: (self.k.ClosePseudoConsole(self.hpc), self.k.CloseHandle(self.sortie)), daemon=True).start()
        self.k.CloseHandle(self.entree)
        self.k.CloseHandle(self.processus)


class FluxSocket:
    """Le serveur VNC local, vu comme un flux du canal."""

    def __init__(self, sock):
        self.sock = sock
        sock.settimeout(None)

    def lire(self):
        try:
            return self.sock.recv(65536)
        except OSError:
            return b''

    def ecrire(self, data):
        try:
            self.sock.sendall(data)
        except OSError:
            pass

    def taille(self, cols, rows):
        pass

    def fermer(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


# ---------------------------------------------------------------------------
# Le canal permanent : une connexion WebSocket que l'agent ouvre lui-même vers
# la console (aucun port à ouvrir sur le poste), TLS vérifié comme les
# remontées (autorité ou empreinte épinglée), authentifiée par le jeton.
# ---------------------------------------------------------------------------

GUID_WS = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'  # RFC 6455, §1.3
TRAME_MAX = 16 * 1024 * 1024


class CanalRefuse(Exception):
    pass


def masquer(data, cle):
    n = len(data)
    if not n:
        return b''
    motif = (cle * (n // 4 + 1))[:n]
    return (int.from_bytes(data, 'big') ^ int.from_bytes(motif, 'big')).to_bytes(n, 'big')


def contexte_tls(cfg):
    """Mêmes chemins que session_http : empreinte épinglée, sinon autorité
    (fichier NEXARC_CA, ou les autorités que requests utilise)."""
    if cfg.get('pin'):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE   # remplacé par la comparaison de l'empreinte, avant tout envoi
        return ctx, normaliser_empreinte(cfg['pin'])
    import requests.certs
    lot = cfg.get('ca') or os.environ.get('REQUESTS_CA_BUNDLE') or os.environ.get('CURL_CA_BUNDLE') or requests.certs.where()
    return ssl.create_default_context(cafile=lot), None


class Canal:
    def __init__(self, cfg, reveil, ecran):
        self.cfg, self.reveil, self.ecran = cfg, reveil, ecran
        self.base = cfg['url'].rstrip('/')
        self.sock = None
        self.tampon = b''
        self.envoi = threading.Lock()
        self.flux = {}
        self.dernier_bonjour = 0
        self.dernier_etat = None

    def demarrer(self):
        threading.Thread(target=self._boucle, daemon=True, name='canal').start()

    def _boucle(self):
        attente, etat = 5, None
        while True:
            debut = time.time()
            try:
                self._connecter()
                if etat != 'ok':
                    journal('[nexarc-agent] canal ouvert : prise en main et tâches immédiates disponibles')
                etat, attente = 'ok', 5
                self._lire()
            except CanalRefuse as e:
                if etat != str(e):
                    journal('[nexarc-agent] canal refusé :', e)
                etat = str(e)
                attente = ATTENTE_JETON_REFUSE if '401' in str(e) else 15 * 60
            except (OSError, ValueError, ssl.SSLError) as e:
                if etat != 'reseau':
                    journal('[nexarc-agent] canal coupé :', e)
                etat = 'reseau'
            finally:
                self._nettoyer()
            if time.time() - debut > 120:
                attente = 5
            time.sleep(attente + secrets.randbelow(5))
            attente = min(attente * 2, 300) if attente < ATTENTE_JETON_REFUSE else attente

    def _connecter(self):
        u = urllib.parse.urlsplit(self.base)
        tls = u.scheme == 'https'
        port = u.port or (443 if tls else 80)
        brut = socket.create_connection((u.hostname, port), timeout=20)
        try:
            if tls:
                ctx, fp = contexte_tls(self.cfg)
                s = ctx.wrap_socket(brut, server_hostname=u.hostname)
                if fp and hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest() != fp:
                    s.close()
                    raise ssl.SSLError('certificat de la console différent de l\'empreinte épinglée')
            else:
                s = brut
            cle = base64.b64encode(os.urandom(16)).decode()
            hote = u.hostname if ':' not in u.hostname else '[%s]' % u.hostname
            if u.port:
                hote += ':%d' % u.port
            s.sendall(('GET %s/api/agent/canal HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                       'Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nX-Agent-Token: %s\r\nUser-Agent: nexarc-agent/%s\r\n\r\n'
                       % (u.path.rstrip('/'), hote, cle, self.cfg['token'], VERSION)).encode())
            s.settimeout(20)
            reponse = b''
            while b'\r\n\r\n' not in reponse:
                bout = s.recv(4096)
                if not bout or len(reponse) > 16384:
                    raise OSError('réponse de mise à niveau incomplète')
                reponse += bout
            tete, _, reste = reponse.partition(b'\r\n\r\n')
            lignes = tete.decode('latin1').split('\r\n')
            code = lignes[0].split(' ')[1] if len(lignes[0].split(' ')) > 1 else ''
            if code in ('401', '403'):
                raise CanalRefuse('jeton refusé (%s)' % code)
            if code == '404':
                raise CanalRefuse('console sans canal (version antérieure à 2.7.0)')
            if code != '101':
                raise OSError('mise à niveau refusée (%s)' % (code or '?'))
            entetes = {l.split(':', 1)[0].strip().lower(): l.split(':', 1)[1].strip() for l in lignes[1:] if ':' in l}
            attendu = base64.b64encode(hashlib.sha1((cle + GUID_WS).encode()).digest()).decode()
            if entetes.get('sec-websocket-accept') != attendu:
                raise OSError('poignée de main WebSocket invalide')
        except BaseException:
            brut.close()
            raise
        # La console envoie un ping toutes les 25 s : 90 s de silence, la
        # connexion est morte et l'agent la rouvre.
        s.settimeout(90)
        self.sock, self.tampon = s, reste
        self.bonjour()

    def capacites(self):
        prise = self.cfg.get('prise_en_main', True)
        etat, raison = self.ecran.etat()
        return {'terminal': bool(prise), 'ecran': {'etat': etat, 'raison': raison}, 'alimentation': True, 'maj': True}

    def bonjour(self):
        cap = self.capacites()
        self.dernier_bonjour, self.dernier_etat = time.time(), json.dumps(cap, sort_keys=True)
        self.envoyer({'t': 'bonjour', 'version': VERSION, 'capacites': cap})

    def bonjour_si_change(self):
        if self.sock is None:
            return
        cap = json.dumps(self.capacites(), sort_keys=True)
        if cap != self.dernier_etat:
            self.bonjour()

    def _nettoyer(self):
        for f in list(self.flux.values()):
            f.fermer()
        self.flux.clear()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None

    def _exact(self, n):
        while len(self.tampon) < n:
            bout = self.sock.recv(max(65536, n - len(self.tampon)))
            if not bout:
                raise OSError('connexion fermée par la console')
            self.tampon += bout
        d, self.tampon = self.tampon[:n], self.tampon[n:]
        return d

    def _lire(self):
        morceaux, op_courant = [], None
        while True:
            b0, b1 = self._exact(2)
            fin, op, n = b0 & 0x80, b0 & 0x0f, b1 & 0x7f
            if b1 & 0x80:
                raise OSError('trame de la console masquée')
            if n == 126:
                n = struct.unpack('>H', self._exact(2))[0]
            elif n == 127:
                n = struct.unpack('>Q', self._exact(8))[0]
            if n > TRAME_MAX:
                raise OSError('trame démesurée')
            charge = self._exact(n)
            if op == 0x9:
                self._envoyer(0xA, charge)
                continue
            if op == 0xA:
                continue
            if op == 0x8:
                self._envoyer(0x8, charge[:2])
                raise OSError('canal fermé par la console')
            if op in (0x1, 0x2):
                op_courant, morceaux = op, [charge]
            elif op == 0x0 and op_courant:
                morceaux.append(charge)
            else:
                raise OSError('trame inattendue')
            if fin:
                message = b''.join(morceaux)
                if op_courant == 0x1:
                    self._controle(message)
                else:
                    self._donnees(message)
                op_courant, morceaux = None, []
            if time.time() - self.dernier_bonjour > 300:
                threading.Thread(target=self.bonjour_si_change, daemon=True).start()
                self.dernier_bonjour = time.time()

    def _envoyer(self, op, charge):
        cle = os.urandom(4)
        n = len(charge)
        tete = bytes([0x80 | op]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack('>H', n) if n < 65536
                                      else bytes([0x80 | 127]) + struct.pack('>Q', n))
        with self.envoi:
            if self.sock is None:
                return
            try:
                self.sock.sendall(tete + cle + masquer(charge, cle))
            except OSError:
                try:
                    self.sock.close()
                except OSError:
                    pass

    def envoyer(self, obj):
        self._envoyer(0x1, json.dumps(obj).encode())

    def _donnees(self, message):
        if len(message) < 4:
            return
        f = self.flux.get(struct.unpack('>I', message[:4])[0])
        if f:
            f.ecrire(message[4:])

    def _controle(self, message):
        try:
            m = json.loads(message.decode('utf-8'))
        except ValueError:
            return
        if not isinstance(m, dict):
            return
        t, ident = m.get('t'), m.get('flux')
        if t == 'taches':
            self.reveil.set()
        elif t == 'ouvrir' and isinstance(ident, int):
            threading.Thread(target=self._ouvrir, args=(ident, m), daemon=True, name='flux-%d' % ident).start()
        elif t == 'fermer':
            f = self.flux.pop(ident, None)
            if f:
                f.fermer()
        elif t == 'taille':
            f = self.flux.get(ident)
            if f:
                f.taille(borne(m.get('cols'), 10, 500, 100), borne(m.get('rows'), 5, 300, 30))

    def _ouvrir(self, ident, m):
        if not self.cfg.get('prise_en_main', True):
            return self.envoyer({'t': 'refus', 'flux': ident, 'raison': 'prise en main désactivée sur ce poste'})
        mdp = None
        try:
            if m.get('type') == 'terminal':
                cols, rows = borne(m.get('cols'), 10, 500, 100), borne(m.get('rows'), 5, 300, 30)
                f = TerminalWindows(cols, rows) if IS_WIN else TerminalPosix(cols, rows)
            elif m.get('type') == 'ecran':
                if self.ecran.etat()[0] == 'a-installer':
                    self.ecran.preparer_en_fond(fin=self.bonjour_si_change)
                    self.bonjour_si_change()
                sock, mdp = self.ecran.ouvrir()
                f = FluxSocket(sock)
            else:
                return self.envoyer({'t': 'refus', 'flux': ident, 'raison': 'type de flux inconnu'})
        except (Indisponible, OSError) as e:
            return self.envoyer({'t': 'refus', 'flux': ident, 'raison': str(e)[:280]})
        self.flux[ident] = f
        journal('[nexarc-agent] prise en main : %s ouvert' % m.get('type'))
        self.envoyer({'t': 'ouvert', 'flux': ident, **({'motDePasse': mdp} if mdp else {})})
        tete = struct.pack('>I', ident)
        while True:
            d = f.lire()
            if not d:
                break
            self._envoyer(0x2, tete + d)
        if self.flux.pop(ident, None) is f:
            f.fermer()
            self.envoyer({'t': 'ferme', 'flux': ident})
        journal('[nexarc-agent] prise en main : %s fermé' % m.get('type'))


def borne(v, mini, maxi, defaut):
    try:
        return max(mini, min(maxi, int(v)))
    except (TypeError, ValueError):
        return defaut


# La mise à jour d'elle-même est retentée au plus une fois l'heure pour une
# même empreinte : un échec (disque plein, droits) ne boucle pas.
_MAJ_TENTEE = {}


def poll_jobs(sess, base, headers, timeout, ctx=None):
    inventaire_a_refaire = False
    try:
        r = sess.post(base + '/api/agent/jobs', json={}, headers=headers, timeout=10)
        if r.status_code != 200:
            return False
        lot = r.json()
        job_timeout = int(lot.get('timeout', timeout))
    except (requests.RequestException, ValueError):
        return False
    if ctx is None:
        ctx = {}
    ctx.update(sess=sess, base=base, headers=headers)
    for job in lot.get('jobs', []):
        journal('[nexarc-agent] tâche %s %s' % (job.get('id'), job.get('kind')))
        rc, out = run_job(job, job_timeout, ctx)
        if job.get('kind') in ('install', 'uninstall', 'inventory', 'update'):
            inventaire_a_refaire = True
        try:
            sess.post('%s/api/agent/jobs/%s/result' % (base, job['id']), json={'output': out[-SORTIE_MAX:], 'rc': rc}, headers=headers, timeout=15)
        except requests.RequestException as e:
            journal('[nexarc-agent] résultat non transmis :', e)
    # Le code distribué par la console a changé : l'agent se met à jour seul
    # (sauf « maj_auto »: false dans agent.json).
    distribue = (lot.get('agent') or {}).get('sha256') if isinstance(lot.get('agent'), dict) else None
    if distribue and FP_SHA256.match(distribue) and ctx.get('maj_auto', True) and distribue != empreinte_code() \
            and time.time() - _MAJ_TENTEE.get(distribue, 0) > 3600:
        _MAJ_TENTEE[distribue] = time.time()
        rc, out = mettre_a_jour(sess, base, headers, distribue)
        journal('[nexarc-agent] mise à jour automatique : %s' % out)
    return inventaire_a_refaire


def lire_config():
    for source in (CONFIG_FILE, os.environ.get('NEXARC_CONFIG', '')):
        if source and os.path.exists(source):
            try:
                with open(source) as f:
                    c = json.load(f)
                if c.get('url') and c.get('token'):
                    return c
            except (OSError, ValueError):
                pass  # fichier illisible ou mal formé : la source suivante, sinon aucune
    return None


# SYSTEM et Administrateurs par leur SID : les noms de groupe changent avec la
# langue de Windows, pas les SID.
ACL_WINDOWS = ['*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F']


def restreindre_dossier():
    """Le jeton va dans ce dossier : lisible par l'agent (root, SYSTEM) seul.
    Sous Windows, un dossier de ProgramData hérite de la lecture pour tous les
    utilisateurs ; chmod n'y peut rien, les ACL si."""
    if IS_WIN:
        rc, out = run(['icacls', CONFIG_DIR, '/inheritance:r', '/grant:r'] + ACL_WINDOWS, 30)
        if rc != 0:
            raise OSError('droits du dossier de l\'agent non posés : %s' % out.strip()[:200])
    else:
        os.chmod(CONFIG_DIR, 0o700)


def ecrire_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    restreindre_dossier()
    provisoire = CONFIG_FILE + '.tmp'
    fd = os.open(provisoire, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(cfg, f)
    os.replace(provisoire, CONFIG_FILE)
    # Un fichier provisoire resté d'une écriture interrompue garde ses droits
    # d'avant à l'ouverture : ils sont resserrés, et un échec n'est pas tu.
    os.chmod(CONFIG_FILE, 0o600)


def echanger_code(sess, url, code):
    r = sess.post(url.rstrip('/') + '/api/enroll/config', json={'code': code}, timeout=20)
    if r.status_code != 200:
        raise RuntimeError('code d\'inscription refusé (%s)' % r.status_code)
    return r.json()['token']


def self_install(url):
    exe_py = os.path.abspath(sys.argv[0])
    dest = os.path.join(CONFIG_DIR, 'nexarc-agent.py')
    if os.path.abspath(dest) != exe_py:
        import shutil
        shutil.copy2(exe_py, dest)
    py = sys.executable
    if IS_WIN:
        ps = ('$a=New-ScheduledTaskAction -Execute "%s" -Argument "%s";'
              '$t=New-ScheduledTaskTrigger -AtStartup;'
              '$p=New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest;'
              '$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries '
              '-RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 999;'
              'Register-ScheduledTask -TaskName "NexarcAgent" -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null;'
              'Start-ScheduledTask -TaskName "NexarcAgent"' % (py, dest))
        return run(['powershell', '-NoProfile', '-Command', ps], 60)
    if IS_MAC:
        plist = '/Library/LaunchDaemons/fr.nexarc.agent.plist'
        with open(plist, 'w') as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
                    '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>'
                    '<key>Label</key><string>fr.nexarc.agent</string>'
                    '<key>ProgramArguments</key><array><string>%s</string><string>%s</string></array>'
                    '<key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>\n' % (py, dest))
        os.chmod(plist, 0o644)
        run(['launchctl', 'unload', plist])
        return run(['launchctl', 'load', '-w', plist])
    unit = '/etc/systemd/system/nexarc-agent.service'
    with open(unit, 'w') as f:
        f.write('[Unit]\nDescription=NEXARC monitoring agent\nAfter=network-online.target\nWants=network-online.target\n\n'
                '[Service]\nType=simple\nExecStart=%s %s\nRestart=always\nRestartSec=15\n\n'
                '[Install]\nWantedBy=multi-user.target\n' % (py, dest))
    run(['systemctl', 'daemon-reload'])
    return run(['systemctl', 'enable', '--now', 'nexarc-agent'])


def bootstrap(a):
    url = os.environ.get('NEXARC_URL', a.url or '')
    code = os.environ.get('NEXARC_ENROLL_CODE', '')
    site = os.environ.get('NEXARC_SITE', a.site or 'Agents')
    nom = os.environ.get('NEXARC_NAME', a.name or '')
    relais = os.environ.get('NEXARC_RELAY', '') in ('1', 'true', 'yes')
    if not url or not code:
        sys.exit('NEXARC_URL et NEXARC_ENROLL_CODE requis pour l\'inscription.')
    try:
        sess = session_http(url, pin=os.environ.get('NEXARC_PIN'), ca=os.environ.get('NEXARC_CA'))
    except ValueError as e:
        sys.exit('NEXARC_PIN : %s' % e)
    print('→ Inscription auprès de %s' % url)
    try:
        token = echanger_code(sess, url, code)
    except (requests.RequestException, RuntimeError, ValueError) as e:
        sys.exit('inscription impossible : %s' % e)
    cfg = {'url': url.rstrip('/'), 'token': token, 'site': site, 'name': nom, 'relais': relais}
    if os.environ.get('NEXARC_PIN'):
        cfg['pin'] = os.environ['NEXARC_PIN']
    if os.environ.get('NEXARC_CA'):
        cfg['ca'] = os.environ['NEXARC_CA']
    try:
        ecrire_config(cfg)
    except OSError as e:
        sys.exit('jeton non rangé : %s' % e)
    print('→ Vérification de la remontée')
    headers = {'X-Agent-Token': token}
    payload = collect(site, nom, relais)
    payload['inventory'] = collect_inventory()
    if not relais:
        payload['software'] = collect_software()
        payload['updates'] = collect_updates()
    try:
        r = sess.post(cfg['url'] + '/api/ingest', json=payload, headers=headers, timeout=60)
        if r.status_code != 200:
            sys.exit('la console a répondu %s : %s' % (r.status_code, r.text[:200]))
    except requests.RequestException as e:
        sys.exit('console injoignable : %s' % e)
    print('→ Installation du service')
    try:
        rc, out = self_install(cfg['url'])
    except PermissionError:
        sys.exit('droits administrateur requis (sudo, ou clic droit → administrateur).')
    if rc != 0:
        sys.exit('service non installé : %s' % out[:200])
    print('→ Service installé et démarré.')


def boucle(cfg, a):
    base = cfg['url'].rstrip('/')
    sess = session_http(base, pin=cfg.get('pin'), ca=cfg.get('ca'))
    headers = {'X-Agent-Token': cfg['token'], 'Content-Type': 'application/json'}
    site, nom = cfg.get('site', 'Agents'), cfg.get('name', '')
    relais = cfg.get('relais', False)
    inv_tous = 12
    cycle = inv_tous
    etat = None  # dernier état journalisé : une ligne par changement, pas une par remontée
    journal('[nexarc-agent] %s démarré, console %s' % (VERSION, base))
    # Le canal : la console y signale une tâche (relevée tout de suite) et y
    # ouvre l'écran ou le terminal. Sans lui, l'agent marche comme avant.
    reveil = threading.Event()
    ecran = Ecran(cfg)
    canal = Canal(cfg, reveil, ecran)
    canal_lance = not cfg.get('canal', True)
    ctx = {'ecran': ecran, 'canal': canal, 'maj_auto': cfg.get('maj_auto', True)}
    prochaine = 0
    while True:
        if time.time() < prochaine:
            # Réveillé par le canal : seulement les tâches, la remontée suit son rythme.
            try:
                if poll_jobs(sess, base, headers, a.job_timeout, ctx):
                    cycle = inv_tous
            except requests.RequestException as e:
                journal('[nexarc-agent] tâches :', e)
            reveil.wait(max(0.5, prochaine - time.time()))
            reveil.clear()
            continue
        prochaine = time.time() + max(5, a.interval)
        try:
            payload = collect(site, nom, relais)
            if cycle >= inv_tous:
                if relais:
                    inv = collect_inventory()
                    payload['inventory'] = {'hostname': inv.get('hostname'), 'nics': inv.get('nics', [])}
                else:
                    payload['inventory'] = collect_inventory()
                    payload['software'] = collect_software()
                    payload['updates'] = collect_updates()
                cycle = 0
            cycle += 1
            r = sess.post(base + '/api/ingest', json=payload, headers=headers, timeout=30)
            if r.status_code == 200:
                if etat != 200:
                    journal('[nexarc-agent] remontées acceptées')
                # Le canal après une première remontée acceptée : à l'inscription,
                # c'est elle qui crée la machine que le jeton désigne.
                if not canal_lance:
                    canal_lance = True
                    canal.demarrer()
            elif r.status_code == 401:
                journal('[nexarc-agent] jeton refusé (révoqué ou machine supprimée) : réinscription nécessaire ; nouvel essai dans %d min.' % (ATTENTE_JETON_REFUSE // 60))
                etat = 401
                time.sleep(ATTENTE_JETON_REFUSE)
                continue
            elif etat != r.status_code:
                journal('[nexarc-agent] la console a répondu %s' % r.status_code)
            etat = r.status_code
        except requests.RequestException as e:
            if etat != 'reseau':
                journal('[nexarc-agent] console injoignable :', e)
            etat = 'reseau'
        try:
            if poll_jobs(sess, base, headers, a.job_timeout, ctx):
                cycle = inv_tous
        except requests.RequestException as e:
            journal('[nexarc-agent] tâches :', e)
        reveil.wait(max(0.5, prochaine - time.time()))
        reveil.clear()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--url', default=os.environ.get('NEXARC_URL'))
    p.add_argument('--site', default=os.environ.get('NEXARC_SITE', 'Agents'))
    p.add_argument('--name', default=os.environ.get('NEXARC_NAME', ''))
    p.add_argument('--interval', type=int, default=int(os.environ.get('NEXARC_INTERVAL', '30')))
    p.add_argument('--job-timeout', dest='job_timeout', type=int, default=int(os.environ.get('NEXARC_JOB_TIMEOUT', '120')))
    p.add_argument('--enroller', action='store_true', help='échanger le code, ranger le jeton, poser le service')
    p.add_argument('--once', action='store_true', help='une remontée puis quitter (auto-test)')
    a = p.parse_args()

    if a.enroller:
        bootstrap(a)
        return
    cfg = lire_config()
    if not cfg:
        sys.exit('Aucune configuration : lance d\'abord --enroller (NEXARC_URL + NEXARC_ENROLL_CODE).')
    if a.once:
        sess = session_http(cfg['url'], pin=cfg.get('pin'), ca=cfg.get('ca'))
        payload = collect(cfg.get('site', 'Agents'), cfg.get('name', ''), cfg.get('relais', False))
        r = sess.post(cfg['url'].rstrip('/') + '/api/ingest', json=payload, headers={'X-Agent-Token': cfg['token']}, timeout=45)
        sys.exit(0 if r.status_code == 200 else 'échec : le serveur a répondu %s' % r.status_code)
    boucle(cfg, a)


if __name__ == '__main__':
    main()
