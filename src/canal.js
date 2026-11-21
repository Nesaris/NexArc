// Canal permanent d'un agent : une connexion WebSocket que l'agent ouvre
// lui-même vers NEXARC (aucun port à ouvrir sur la machine), authentifiée par
// SON jeton, et par laquelle passent :
//   - le réveil des tâches : une tâche créée part tout de suite, sans attendre
//     la prochaine relève ;
//   - des flux ouverts à la demande d'un opérateur : l'écran (le serveur VNC
//     local de la machine, réglé par l'agent) et le terminal.
//
// Protocole, côté fil :
//   - messages texte : JSON de contrôle ;
//       serveur → agent : { t:'ouvrir', flux, type, cols?, rows? } · { t:'fermer', flux }
//                         { t:'taille', flux, cols, rows } · { t:'taches' }
//       agent → serveur : { t:'bonjour', version, capacites } · { t:'ouvert', flux, motDePasse? }
//                         { t:'refus', flux, raison } · { t:'ferme', flux }
//   - messages binaires : 4 octets d'identifiant de flux (gros-boutiste), puis
//     les octets du flux.
//
// Un flux est refusé par l'agent s'il ne sait pas le servir (pas d'écran sur
// un serveur sans affichage, par exemple), et chaque flux ouvert l'est au nom
// d'un opérateur déjà contrôlé par l'appelant (rôle, renfort, journal).
import { EventEmitter } from 'node:events';

const TYPES = new Set(['ecran', 'terminal']);
const FLUX_PAR_MACHINE = 4;
const OUVERTURE_MS = 25000;          // l'agent peut devoir installer ou lancer son serveur d'écran
const BATTEMENT_MS = 25000;
const MAX_ETAT = 400;                // une raison, une version : du texte court

const texteCourt = (v, n = MAX_ETAT) => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, n);

// Ce que l'agent dit savoir faire, réduit à un vocabulaire fermé : l'interface
// n'affiche jamais un texte d'agent comme du balisage, et rien d'autre ne passe.
export function capacitesSures(c) {
  const ecran = c && typeof c === 'object' && c.ecran && typeof c.ecran === 'object' ? c.ecran : {};
  const etats = new Set(['pret', 'a-installer', 'a-activer', 'indisponible']);
  return {
    terminal: !!(c && c.terminal),
    ecran: { etat: etats.has(ecran.etat) ? ecran.etat : 'indisponible', raison: texteCourt(ecran.raison, 300) },
    alimentation: !!(c && c.alimentation),
    maj: !!(c && c.maj),           // sait se mettre à jour (tâche « agent-maj »)
  };
}

// Un flux, vu du serveur : comme une socket (write, destroy, data, close),
// pour que le pont VNC et le terminal le traitent comme une connexion.
export class FluxAgent extends EventEmitter {
  constructor(canal, id, type) {
    super();
    this.canal = canal; this.id = id; this.type = type; this.ferme = false; this.infos = {};
    // L'agent écrit dès l'ouverture (le serveur VNC parle le premier), parfois
    // dans le même paquet que « ouvert » : ce qui arrive avant que l'appelant
    // n'écoute est gardé, puis rendu à son premier écouteur.
    this._attente = []; this._enAttente = 0;
    this.on('newListener', ev => { if (ev === 'data' && this._attente.length) process.nextTick(() => this._vider()); });
  }
  _recevoir(b) {
    if (this.listenerCount('data')) { this.emit('data', b); return; }
    this._enAttente += b.length;
    if (this._enAttente > 1 << 20) { this.destroy(); return; }   // personne n'écoute : on coupe
    this._attente.push(Buffer.from(b));
  }
  _vider() {
    const t = this._attente; this._attente = []; this._enAttente = 0;
    for (const b of t) this.emit('data', b);
  }
  write(buf) {
    if (this.ferme) return false;
    const tete = Buffer.alloc(4); tete.writeUInt32BE(this.id, 0);
    this.canal.conn.envoyerBinaire(Buffer.concat([tete, Buffer.isBuffer(buf) ? buf : Buffer.from(buf)]));
    return true;
  }
  taille(cols, rows) {
    if (this.ferme) return;
    const c = Math.max(10, Math.min(500, Number(cols) | 0)), r = Math.max(5, Math.min(300, Number(rows) | 0));
    this.canal.envoyer({ t: 'taille', flux: this.id, cols: c, rows: r });
  }
  // Comme net.Socket : un délai d'inactivité (0 l'annule), pour qu'un agent
  // muet ne garde pas une poignée de main ouverte sans fin.
  setTimeout(ms, rappel) {
    clearTimeout(this._delai);
    if (ms > 0 && rappel) this._delai = setTimeout(rappel, ms);
    return this;
  }
  setNoDelay() { return this; }
  end() { this.destroy(); }
  destroy() {
    if (this.ferme) return;
    this.canal.envoyer({ t: 'fermer', flux: this.id });
    this._clore();
  }
  _clore() {
    if (this.ferme) return;
    this.ferme = true;
    clearTimeout(this._delai);
    this.canal.flux.delete(this.id);
    this.emit('close');
  }
}

class Canal {
  constructor(conn, machine) {
    this.conn = conn; this.machineId = machine.id; this.ref = machine.ref; this.host = machine.host;
    this.flux = new Map(); this.attentes = new Map(); this.prochain = 1;
    this.version = ''; this.capacites = capacitesSures({}); this.depuis = Date.now();
  }
  envoyer(obj) { this.conn.envoyerTexte(JSON.stringify(obj)); }
}

export class Canaux {
  constructor({ log = null } = {}) {
    this.parMachine = new Map();
    this.parRef = new Map();
    this.log = log;
    this.surChangement = null;
    this.battement = setInterval(() => { for (const c of this.parMachine.values()) c.conn.ping(); }, BATTEMENT_MS);
    this.battement.unref?.();
  }

  arreter() {
    clearInterval(this.battement);
    for (const c of this.parMachine.values()) { try { c.conn.close(); } catch { /* déjà fermé */ } }
    this.parMachine.clear(); this.parRef.clear();
  }

  // Branche la connexion d'un agent déjà authentifié. Un seul canal par
  // machine : le plus récent remplace l'autre (agent redémarré, réseau revenu).
  brancher(conn, machine) {
    const ancien = this.parMachine.get(machine.id);
    if (ancien) this._fermer(ancien, 'remplacé');
    const canal = new Canal(conn, machine);
    this.parMachine.set(machine.id, canal);
    this.parRef.set(machine.ref, canal);
    conn.on('texte', t => this._controle(canal, t));
    conn.on('binaire', b => this._donnees(canal, b));
    conn.on('fermeture', () => {
      if (this.parMachine.get(machine.id) !== canal) return;
      this.parMachine.delete(machine.id); this.parRef.delete(machine.ref);
      this._fermer(canal, 'déconnecté'); this.surChangement?.(machine.id);
    });
    this.surChangement?.(machine.id);
    return canal;
  }

  _fermer(canal, raison) {
    for (const f of canal.flux.values()) f._clore();
    for (const a of canal.attentes.values()) a.rejeter(new Error(`agent ${raison}`));
    canal.attentes.clear();
    try { canal.conn.close(); } catch { /* déjà fermé */ }
  }

  _controle(canal, texte) {
    let m;
    try { m = JSON.parse(texte); } catch { return; }
    if (!m || typeof m !== 'object') return;
    const id = Number(m.flux);
    if (m.t === 'bonjour') {
      canal.version = texteCourt(m.version, 40);
      canal.capacites = capacitesSures(m.capacites);
      this.surChangement?.(canal.machineId);
    } else if (m.t === 'ouvert' && canal.attentes.has(id)) {
      const a = canal.attentes.get(id); canal.attentes.delete(id);
      const f = new FluxAgent(canal, id, a.type);
      // Le mot de passe du serveur VNC local, pour que le pont s'authentifie :
      // jamais gardé ailleurs qu'en mémoire, le temps de la connexion.
      if (typeof m.motDePasse === 'string') f.infos.motDePasse = m.motDePasse.slice(0, 64);
      canal.flux.set(id, f);
      a.resoudre(f);
    } else if (m.t === 'refus' && canal.attentes.has(id)) {
      const a = canal.attentes.get(id); canal.attentes.delete(id);
      a.rejeter(new Error(texteCourt(m.raison, 300) || 'refusé par l\'agent'));
    } else if (m.t === 'ferme') {
      canal.flux.get(id)?._clore();
    }
  }

  _donnees(canal, b) {
    if (b.length < 4) return;
    const f = canal.flux.get(b.readUInt32BE(0));
    if (f) f._recevoir(b.subarray(4));
  }

  connecte(machineId) { return this.parMachine.has(machineId); }

  // Ce que l'interface montre d'un canal : connecté ou non, et ce que l'agent sait faire.
  etatPublic(machineId) { return this._etat(this.parMachine.get(machineId)); }
  etatParRef(ref) { return this._etat(this.parRef.get(ref)); }
  _etat(c) {
    if (!c) return { connecte: false };
    return { connecte: true, version: c.version, depuis: Math.floor(c.depuis / 1000), ...c.capacites };
  }

  // Une tâche vient d'être créée : l'agent la relève tout de suite.
  signaler(machineId) {
    const c = this.parMachine.get(machineId);
    if (c) { try { c.envoyer({ t: 'taches' }); } catch { /* le canal se ferme de lui-même */ } }
    return !!c;
  }

  // Demande à l'agent un flux ; rend un FluxAgent une fois l'agent prêt.
  ouvrir(machineId, type, { cols = 100, rows = 30 } = {}) {
    const c = this.parMachine.get(machineId);
    if (!TYPES.has(type)) return Promise.reject(new Error('type de flux inconnu'));
    if (!c) return Promise.reject(new Error('l\'agent de cette machine n\'est pas connecté'));
    if (c.flux.size + c.attentes.size >= FLUX_PAR_MACHINE) return Promise.reject(new Error('trop de sessions ouvertes sur cette machine'));
    const id = c.prochain++;
    if (c.prochain > 0x7fffffff) c.prochain = 1;
    return new Promise((resoudre, rejeter) => {
      const minuterie = setTimeout(() => { if (c.attentes.delete(id)) { c.envoyer({ t: 'fermer', flux: id }); rejeter(new Error('l\'agent n\'a pas répondu à temps')); } }, OUVERTURE_MS);
      c.attentes.set(id, {
        type,
        resoudre: f => { clearTimeout(minuterie); resoudre(f); },
        rejeter: e => { clearTimeout(minuterie); rejeter(e); },
      });
      c.envoyer({ t: 'ouvrir', flux: id, type, cols: Math.max(10, Math.min(500, cols | 0)), rows: Math.max(5, Math.min(300, rows | 0)) });
    });
  }
}
