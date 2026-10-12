"""Essais de l'agent NEXARC (unittest, bibliothèque standard).

    python3 -m unittest agent/test_agent.py

Le point central : la vérification TLS. Sans empreinte épinglée, l'autorité
(système ou fichier NEXARC_CA) vérifie toujours ; verify=False n'apparaît
qu'avec une empreinte bien formée, et alors seul le certificat épinglé passe.
Prouvé contre un vrai serveur HTTPS local, pas sur des objets simulés.

Le certificat d'essai vient de l'aide du socle (socle/essai/smtp.js), lancée
par Node : la bibliothèque standard de Python ne sait pas en fabriquer un.
"""
import hashlib
import importlib.util
import json
import os
import re
import shutil
import ssl
import stat
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ICI = os.path.dirname(os.path.abspath(__file__))
RACINE = os.path.dirname(ICI)

# Le serveur d'essai est local : aucun relais sortant ne doit s'interposer.
os.environ['NO_PROXY'] = os.environ['no_proxy'] = '127.0.0.1,localhost'

spec = importlib.util.spec_from_file_location('nexarc_agent', os.path.join(ICI, 'nexarc-agent.py'))
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)

import requests  # noqa: E402 — après l'agent, qui dit quoi installer s'il manque


def node():
    return os.environ.get('NODE') or shutil.which('node24') or shutil.which('node')


def certificat_essai(dossier):
    """(chemin du certificat, chemin de la clé) signés par eux-mêmes, CN=localhost, IP 127.0.0.1."""
    script = ("import(process.argv[1]).then(m => process.stdout.write(JSON.stringify(m.certificatEssai('localhost'))))")
    sortie = subprocess.run([node(), '--input-type=module', '-e', script, os.path.join(RACINE, 'socle', 'essai', 'smtp.js')],
                            check=True, capture_output=True, text=True, timeout=60).stdout
    c = json.loads(sortie)
    cert, cle = os.path.join(dossier, 'cert.pem'), os.path.join(dossier, 'cle.pem')
    with open(cert, 'w') as f:
        f.write(c['cert'])
    with open(cle, 'w') as f:
        f.write(c['cle'])
    return cert, cle


class Repond(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 — nom imposé par http.server
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')

    def log_message(self, *a):
        pass  # le journal d'accès n'a rien à dire pendant les essais


@unittest.skipUnless(node(), 'Node introuvable : le certificat d\'essai ne peut pas être fabriqué')
class VerificationTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dossier = tempfile.mkdtemp(prefix='agent-tls-')
        cls.cert, cls.cle = certificat_essai(cls.dossier)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cls.cert, cls.cle)
        cls.serveur = ThreadingHTTPServer(('127.0.0.1', 0), Repond)
        cls.serveur.socket = ctx.wrap_socket(cls.serveur.socket, server_side=True)
        threading.Thread(target=cls.serveur.serve_forever, daemon=True).start()
        cls.url = 'https://127.0.0.1:%d/' % cls.serveur.server_address[1]
        with open(cls.cert) as f:
            cls.fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.serveur.shutdown()
        cls.serveur.server_close()
        shutil.rmtree(cls.dossier, ignore_errors=True)

    # ── sans empreinte : l'autorité vérifie, toujours ──
    def test_sans_empreinte_autorites_du_systeme_refusent_l_autosigne(self):
        s = agent.session_http(self.url)
        self.assertIs(s.verify, True)
        with self.assertRaises(requests.exceptions.SSLError):
            s.get(self.url, timeout=10)

    def test_sans_empreinte_fichier_d_autorite_accepte_ce_qu_il_signe(self):
        s = agent.session_http(self.url, ca=self.cert)
        self.assertEqual(s.verify, self.cert)
        self.assertEqual(s.get(self.url, timeout=10).text, 'ok')

    def test_sans_empreinte_un_autre_fichier_d_autorite_refuse(self):
        autre_dossier = tempfile.mkdtemp(prefix='agent-tls-autre-')
        try:
            autre, _ = certificat_essai(autre_dossier)
            with self.assertRaises(requests.exceptions.SSLError):
                agent.session_http(self.url, ca=autre).get(self.url, timeout=10)
        finally:
            shutil.rmtree(autre_dossier, ignore_errors=True)

    # ── avec empreinte : seul le certificat épinglé passe ──
    def test_empreinte_juste_acceptee(self):
        s = agent.session_http(self.url, pin='sha256:' + ':'.join(self.fp[i:i + 2] for i in range(0, 64, 2)).upper())
        self.assertIs(s.verify, False)
        self.assertIsInstance(s.get_adapter(self.url), agent.EpingleAdapter)
        self.assertEqual(s.get(self.url, timeout=10).text, 'ok')

    def test_empreinte_differente_refusee(self):
        s = agent.session_http(self.url, pin='ab' * 32)
        with self.assertRaises(requests.exceptions.SSLError):
            s.get(self.url, timeout=10)

    def test_empreinte_mal_formee_ne_desactive_rien(self):
        for mauvaise in ('sha256:1234', 'pas-une-empreinte', 'g' * 64):
            with self.assertRaises(ValueError):
                agent.session_http(self.url, pin=mauvaise)

    def test_verify_false_seulement_avec_une_empreinte(self):
        for pin, ca in ((None, None), ('', None), (None, self.cert), ('', self.cert)):
            self.assertIsNot(agent.session_http(self.url, pin=pin, ca=ca).verify, False, (pin, ca))


class Posture(unittest.TestCase):
    def test_antivirus_centre_de_securite(self):
        self.assertEqual(agent.av_securitycenter([]), 'absent')
        self.assertEqual(agent.av_securitycenter([397568]), 'à jour')      # 0x061100 : actif, à jour
        self.assertEqual(agent.av_securitycenter([397584]), 'obsolète')    # 0x061110 : actif, périmé
        self.assertEqual(agent.av_securitycenter([393472]), 'inactif')     # 0x060100 : arrêté
        self.assertEqual(agent.av_securitycenter([393472, 397568]), 'à jour')

    def test_antivirus_defender(self):
        self.assertEqual(agent.av_defender({'AntivirusEnabled': True, 'RealTimeProtectionEnabled': True, 'AntivirusSignatureAge': 1}), 'à jour')
        self.assertEqual(agent.av_defender({'AntivirusEnabled': True, 'RealTimeProtectionEnabled': True, 'AntivirusSignatureAge': 30}), 'obsolète')
        self.assertEqual(agent.av_defender({'AntivirusEnabled': True, 'RealTimeProtectionEnabled': False}), 'inactif')
        self.assertEqual(agent.av_defender({}), 'inactif')

    def test_pare_feu(self):
        self.assertEqual(agent.pare_feu_windows('True,True,True\r\n'), 'actif')
        self.assertEqual(agent.pare_feu_windows('True,False,True'), 'inactif')
        self.assertEqual(agent.pare_feu_windows('Accès refusé'), 'inconnu')
        self.assertEqual(agent.pare_feu_macos('Firewall is enabled. (State = 1)'), 'actif')
        self.assertEqual(agent.pare_feu_macos('Firewall is disabled. (State = 0)'), 'inactif')
        self.assertTrue(agent.iptables_filtre_entree('-P INPUT DROP\n-P FORWARD DROP\n'))
        self.assertTrue(agent.iptables_filtre_entree('-P INPUT ACCEPT\n-A INPUT -p tcp --dport 22 -j ACCEPT\n'))
        self.assertFalse(agent.iptables_filtre_entree('-P INPUT ACCEPT\n'))
        filtre = 'table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tct state established accept\n\t}\n}\n'
        ouvert = 'table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n'
        self.assertTrue(agent.nft_filtre_entree(filtre))
        self.assertFalse(agent.nft_filtre_entree(ouvert))


class Enregistre(BaseHTTPRequestHandler):
    """Serveur NEXARC minimal : note chaque requête, répond comme le vrai."""
    recues = []

    def do_POST(self):  # noqa: N802 — nom imposé par http.server
        corps = self.rfile.read(int(self.headers.get('Content-Length') or 0))
        Enregistre.recues.append((self.command, self.path, self.headers.get('Content-Type'), self.headers.get('X-Agent-Token'), json.loads(corps or b'null')))
        reponse = {'/api/enroll/config': {'token': 'sag_jeton_de_l_essai'},
                   '/api/agent/jobs': {'jobs': [{'id': 'AAAAAAAAAAAAAAAA', 'kind': 'inventory', 'payload': ''}], 'timeout': 5}}.get(self.path, {'ok': True})
        donnees = json.dumps(reponse).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(donnees)))
        self.end_headers()
        self.wfile.write(donnees)

    def log_message(self, *a):
        pass


class Echanges(unittest.TestCase):
    """Échanger un code et relever ses tâches changent l'état du serveur : des
    POST en JSON, jamais des GET qu'un relais ou un journal garderaient."""

    def setUp(self):
        Enregistre.recues = []
        self.serveur = ThreadingHTTPServer(('127.0.0.1', 0), Enregistre)
        threading.Thread(target=self.serveur.serve_forever, daemon=True).start()
        self.url = 'http://127.0.0.1:%d' % self.serveur.server_address[1]

    def tearDown(self):
        self.serveur.shutdown()
        self.serveur.server_close()

    def test_echange_du_code_en_post(self):
        self.assertEqual(agent.echanger_code(agent.session_http(self.url), self.url, 'CODE_D_INSCRIPTION_22c'), 'sag_jeton_de_l_essai')
        self.assertEqual(Enregistre.recues, [('POST', '/api/enroll/config', 'application/json', None, {'code': 'CODE_D_INSCRIPTION_22c'})])

    def test_releve_et_resultat_en_post_avec_le_jeton(self):
        entetes = {'X-Agent-Token': 'sag_jeton_de_l_essai', 'Content-Type': 'application/json'}
        self.assertTrue(agent.poll_jobs(agent.session_http(self.url), self.url, entetes, 5))
        self.assertEqual([r[:4] for r in Enregistre.recues], [
            ('POST', '/api/agent/jobs', 'application/json', 'sag_jeton_de_l_essai'),
            ('POST', '/api/agent/jobs/AAAAAAAAAAAAAAAA/result', 'application/json', 'sag_jeton_de_l_essai')])
        self.assertEqual(Enregistre.recues[1][4], {'output': 'inventaire régénéré', 'rc': 0})


class Durcissement(unittest.TestCase):
    def test_types_de_taches_identiques_au_serveur(self):
        with open(os.path.join(RACINE, 'src', 'taches.js'), encoding='utf-8') as f:
            m = re.search(r"KINDS = new Set\(\[([^\]]+)\]\)", f.read())
        self.assertEqual(agent.KINDS, set(re.findall(r"'([a-z]+)'", m.group(1))))

    def test_motif_de_paquet_identique_au_serveur(self):
        with open(os.path.join(RACINE, 'src', 'taches.js'), encoding='utf-8') as f:
            m = re.search(r"export const PAQUET = /(.+)/;", f.read())
        self.assertEqual(agent.PAQUET.pattern, m.group(1))

    def test_aucun_shell_interprete(self):
        rc, out = agent.run(['echo', 'a; echo b $HOME'])
        self.assertEqual((rc, out.strip()), (0, 'a; echo b $HOME'))

    def test_type_inconnu_et_paquet_invalide_refuses(self):
        self.assertEqual(agent.run_job({'kind': 'reboot', 'payload': ''}, 5)[0], 1)
        self.assertIsNone(agent.pkg_cmd('install', 'paquet; rm -rf /'))
        self.assertIsNone(agent.maj_cmd('$(id)'))

    def test_dossier_windows_ferme_aux_utilisateurs_par_acl(self):
        appels, avant = [], (agent.IS_WIN, agent.run, agent.CONFIG_DIR)
        try:
            agent.IS_WIN, agent.CONFIG_DIR = True, r'C:\ProgramData\NexarcAgent'
            agent.run = lambda cmd, timeout=25, env=None: (appels.append(cmd), (0, ''))[1]
            agent.restreindre_dossier()
            self.assertEqual(appels, [['icacls', r'C:\ProgramData\NexarcAgent', '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F']])
            agent.run = lambda cmd, timeout=25, env=None: (5, 'Accès refusé')
            with self.assertRaises(OSError):
                agent.restreindre_dossier()
        finally:
            agent.IS_WIN, agent.run, agent.CONFIG_DIR = avant

    def test_configuration_ecrite_en_0600(self):
        dossier = tempfile.mkdtemp(prefix='agent-conf-')
        avant = agent.CONFIG_DIR, agent.CONFIG_FILE
        try:
            agent.CONFIG_DIR, agent.CONFIG_FILE = dossier, os.path.join(dossier, 'agent.json')
            agent.ecrire_config({'url': 'https://nexarc.exemple.org', 'token': 'sag_essai'})
            self.assertEqual(stat.S_IMODE(os.stat(agent.CONFIG_FILE).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(dossier).st_mode), 0o700)
        finally:
            agent.CONFIG_DIR, agent.CONFIG_FILE = avant
            shutil.rmtree(dossier, ignore_errors=True)


class Paquets(unittest.TestCase):
    """Les tâches de paquets doivent marcher là où l'agent tourne vraiment :
    en SYSTEM sous Windows, en root par un LaunchDaemon sous macOS, sans
    terminal sous Linux."""

    def setUp(self):
        self.avant = (agent.IS_WIN, agent.IS_MAC, agent.IS_LINUX, agent.shutil.which, agent.run, os.environ.get('ProgramFiles'))

    def tearDown(self):
        agent.IS_WIN, agent.IS_MAC, agent.IS_LINUX, agent.shutil.which, agent.run, pf = self.avant
        if pf is None:
            os.environ.pop('ProgramFiles', None)
        else:
            os.environ['ProgramFiles'] = pf

    def test_winget_retrouve_hors_du_path_de_system(self):
        racine = tempfile.mkdtemp(prefix='pf-')
        try:
            for v in ('1.9.25200.0', '1.23.1911.0', '1.21.10120.0'):
                d = os.path.join(racine, 'WindowsApps', 'Microsoft.DesktopAppInstaller_%s_x64__8wekyb3d8bbwe' % v)
                os.makedirs(d)
                open(os.path.join(d, 'winget.exe'), 'w').close()
            os.environ['ProgramFiles'] = racine
            agent.shutil.which = lambda nom: None
            agent.IS_WIN, agent.IS_MAC, agent.IS_LINUX = True, False, False
            cmd = agent.pkg_cmd('install', 'Mozilla.Firefox')
            self.assertIn('1.23.1911.0', cmd[0], 'la version la plus récente, comparée en nombres')
            self.assertEqual(cmd[1:5], ['install', '-e', '--id', 'Mozilla.Firefox'])
            self.assertIn('--accept-source-agreements', agent.pkg_cmd('uninstall', 'Mozilla.Firefox'))
            shutil.rmtree(os.path.join(racine, 'WindowsApps'))
            self.assertEqual(agent.run_job({'kind': 'install', 'payload': 'Mozilla.Firefox'}, 5), (1, 'winget introuvable sur ce poste (App Installer absent).'))
        finally:
            shutil.rmtree(racine, ignore_errors=True)

    def test_homebrew_lance_au_nom_de_son_proprietaire(self):
        if os.geteuid() != 0:
            self.skipTest('demande root pour poser le propriétaire du faux brew')
        import pwd
        d = tempfile.mkdtemp(prefix='brew-')
        try:
            brew = os.path.join(d, 'brew')
            open(brew, 'w').close()
            nobody = pwd.getpwnam('nobody')
            os.chown(brew, nobody.pw_uid, nobody.pw_gid)
            agent.shutil.which = lambda nom: brew if nom == 'brew' else None
            agent.IS_WIN, agent.IS_MAC, agent.IS_LINUX = False, True, False
            self.assertEqual(agent.pkg_cmd('install', 'tree'), ['/usr/bin/sudo', '-u', 'nobody', '-H', '--', brew, 'install', 'tree'])
            self.assertEqual(agent.maj_cmd(''), ['softwareupdate', '-i', '-a'])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_linux_premier_gestionnaire_present_et_apt_sans_question(self):
        agent.IS_WIN, agent.IS_MAC, agent.IS_LINUX = False, False, True
        agent.shutil.which = lambda nom: '/usr/bin/dnf' if nom == 'dnf' else None
        self.assertEqual(agent.pkg_cmd('install', 'tree'), ['dnf', 'install', '-y', '-q', 'tree'])
        self.assertEqual(agent.maj_cmd(''), ['dnf', 'upgrade', '-y', '-q'])
        agent.shutil.which = lambda nom: '/usr/bin/apt-get' if nom == 'apt-get' else None
        appels = []
        agent.run = lambda cmd, timeout=25, env=None: (appels.append((cmd, (env or {}).get('DEBIAN_FRONTEND'))), (0, 'ok'))[1]
        self.assertEqual(agent.run_job({'kind': 'install', 'payload': 'tree'}, 5), (0, 'ok'))
        self.assertEqual(appels, [(['apt-get', 'update', '-qq'], 'noninteractive'), (['apt-get', 'install', '-y', '-q', 'tree'], 'noninteractive')])
        agent.shutil.which = lambda nom: None
        self.assertEqual(agent.run_job({'kind': 'update', 'payload': ''}, 5)[0], 1)


class ServiceEtJournal(unittest.TestCase):
    def test_journal_dans_un_fichier_borne_hors_linux(self):
        d = tempfile.mkdtemp(prefix='agent-log-')
        avant = (agent.IS_LINUX, agent.JOURNAL_FICHIER, agent.JOURNAL_MAX)
        try:
            agent.IS_LINUX, agent.JOURNAL_FICHIER, agent.JOURNAL_MAX = False, os.path.join(d, 'agent.log'), 200
            for i in range(12):
                agent.journal('[nexarc-agent] ligne', i)
            self.assertTrue(os.path.exists(agent.JOURNAL_FICHIER + '.1'), 'une génération gardée')
            self.assertLessEqual(os.path.getsize(agent.JOURNAL_FICHIER), 200 + 60)
            self.assertFalse(os.path.exists(agent.JOURNAL_FICHIER + '.2'))
            with open(agent.JOURNAL_FICHIER, encoding='utf-8') as f:
                self.assertRegex(f.read().splitlines()[-1], r'^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \[nexarc-agent\] ligne 11$')
        finally:
            agent.IS_LINUX, agent.JOURNAL_FICHIER, agent.JOURNAL_MAX = avant
            shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
