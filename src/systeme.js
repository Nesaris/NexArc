// Le code de l'agent que ce serveur distribue, et sa mise à jour à distance.
//
// Un agent récent sait se mettre à jour (tâche « agent-maj ») : il télécharge
// le code par son jeton, vérifie qu'il a l'empreinte annoncée, le remplace et
// redémarre son service. Un agent d'avant le canal ne connaît pas ce geste :
// il reçoit à la place une tâche « cmd » dont la charge est écrite ICI, par le
// serveur, jamais par un opérateur — c'est pourquoi elle part même quand la
// commande libre est désactivée. Elle fait la même chose avec le code de
// l'agent lui-même (lecture de sa configuration, session TLS vérifiée ou
// épinglée), puis appelle la routine de redémarrage du NOUVEAU code.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export function codeAgent(racine) {
  const code = fs.readFileSync(path.join(racine, 'agent', 'nexarc-agent.py'));
  const version = /^VERSION = '([0-9.]+)'$/m.exec(code.toString('utf8'))?.[1] || '';
  return { code, sha256: crypto.createHash('sha256').update(code).digest('hex'), version };
}

const DOSSIERS = {
  win: { py: '%ProgramData%\\NexarcAgent\\venv\\Scripts\\python.exe', agent: 'os.path.join(os.environ["ProgramData"], "NexarcAgent", "nexarc-agent.py")' },
  mac: { py: '/usr/local/nexarc-agent/venv/bin/python', agent: '"/usr/local/nexarc-agent/nexarc-agent.py"' },
  lin: { py: '/opt/nexarc-agent/venv/bin/python', agent: '"/opt/nexarc-agent/nexarc-agent.py"' },
};

// La charge de la tâche « cmd » pour un agent d'avant 2.7.0. sha : l'empreinte
// attendue (hexadécimal, contrôlé par l'appelant). Le programme Python passe en
// base64. Sous Windows, la commande passe par « cmd.exe /c » : ni espace ni
// guillemet dans l'argument de -c (cmd et la ligne de commande de Windows ne
// s'accordent pas sur leur échappement) ; ailleurs, /bin/sh -c et des
// guillemets doubles autour d'un texte sans $, ` ni \.
export function commandeMiseAJour(oskind, sha) {
  if (!/^[0-9a-f]{64}$/.test(sha)) throw new Error('empreinte invalide');
  const d = DOSSIERS[oskind] || DOSSIERS.lin;
  const programme = [
    'import hashlib, importlib.util, os, sys',
    `chemin = ${d.agent}`,
    'def charger(p, nom):',
    '    spec = importlib.util.spec_from_file_location(nom, p)',
    '    m = importlib.util.module_from_spec(spec)',
    '    spec.loader.exec_module(m)',
    '    return m',
    'ancien = charger(chemin, "nexarc_ancien")',
    'c = ancien.lire_config()',
    's = ancien.session_http(c["url"], pin=c.get("pin"), ca=c.get("ca"))',
    'r = s.get(c["url"].rstrip("/") + "/api/agent/code", headers={"X-Agent-Token": c["token"]}, timeout=60)',
    'r.raise_for_status()',
    `if hashlib.sha256(r.content).hexdigest() != "${sha}": sys.exit("empreinte du code inattendue : rien n'est remplacé")`,
    'tmp = chemin + ".nouveau"',
    'open(tmp, "wb").write(r.content)',
    'os.replace(tmp, chemin)',
    'charger(chemin, "nexarc_nouveau").redemarrer_plus_tard()',
    'print("agent remplacé ; redémarrage du service dans quelques secondes")',
  ].join('\n');
  const b64 = Buffer.from(programme, 'utf8').toString('base64');
  const expr = `exec(__import__('base64').b64decode('${b64}'))`;
  return oskind === 'win' ? `${d.py} -c ${expr}` : `${d.py} -c "${expr}"`;
}
