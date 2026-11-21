// Démarrage de NEXARC : configuration validée, base, socle commun (comptes,
// sessions, coffre), reprise de la 1.x, boucles de collecte et d'automatisation,
// serveur HTTP et mise à niveau WebSocket (pont VNC) écrite à la main, et, si
// son adresse est posée, l'origine à part des consoles web.
import http from 'node:http';
import path from 'node:path';
import { lireConfigNexarc, VERSION, SPEC_NEXARC, REGLAGES_NEXARC } from './config.js';
import { ouvrirBase, Parc } from './base.js';
import { Agents } from './agents.js';
import { Alertes } from './alertes.js';
import { Taches } from './taches.js';
import { Synapse } from './synapse.js';
import { lienDeSecours, migrerComptes, migrerParc } from './migration.js';
import { creerApi } from './api.js';
import { pont, pontFlux } from './vncbridge.js';
import { Canaux } from './canal.js';
import { OrigineConsoles } from './origine-consoles.js';
import { verifierUpgrade, accepter, refuser } from './websocket.js';
import {
  Debit, ErreurHttp, appliquerReglages, demarrerSocle, lireNouveautes, superviser, entetesSecurite, envelopper, nonceCsp, politiqueContenu,
  repondreErreur, repondreJson, servirFichier, origineDe, adresseClient, GAMMES, avecDisposition,
} from '../socle/src/index.js';
import fs from 'node:fs';

const RACINE = path.resolve(import.meta.dirname, '..');
const PAGE = fs.readFileSync(path.join(RACINE, 'web', 'index.html'), 'utf8').replaceAll('__VERSION__', encodeURIComponent(VERSION));
const CONSOLE = { info: (...a) => console.log(...a), warn: (...a) => console.warn(...a), error: (...a) => console.error(...a) };
// Signalement privé d'une faille, sur le dépôt : lu par le mainteneur.
const CONTACT_SECURITE = 'https://github.com/CodexX64/nexarc/security/advisories/new';

// Diffuseur d'activité en direct (SSE). Chaque flux ouvert reçoit les lignes ;
// un flux fermé se retire de lui-même. Un flux tient une connexion ouverte :
// quelques onglets par session, deux cents en tout.
const FLUX_PAR_SESSION = 4, FLUX_MAX = 200;
class Flux {
  constructor() { this.abonnes = new Map(); }
  place(session) {
    return this.abonnes.size < FLUX_MAX && [...this.abonnes.values()].filter(s => s === session).length < FLUX_PAR_SESSION;
  }
  brancher(res, session) {
    this.abonnes.set(res, session);
    res.write(': ok\n\n');
    const battement = setInterval(() => { try { res.write(': ping\n\n'); } catch { /* fermé */ } }, 25000);
    battement.unref?.();
    res.on('close', () => { clearInterval(battement); this.abonnes.delete(res); });
  }
  pousser(obj) {
    const ligne = `data: ${JSON.stringify(obj)}\n\n`;
    for (const res of this.abonnes.keys()) { try { res.write(ligne); } catch { this.abonnes.delete(res); } }
  }
}

export async function demarrer(envBrut = process.env, { log = CONSOLE } = {}) {
  // Les réglages posés par l'assistant complètent l'environnement (qui garde la main).
  const env = appliquerReglages({ dossier: envBrut.DATA_DIR || SPEC_NEXARC.donnees.defaut, env: envBrut });
  const cfg = lireConfigNexarc(env);
  const db = ouvrirBase(cfg.donnees);
  const socle = await demarrerSocle({
    service: { id: 'nexarc', nom: 'NEXARC', contactSecurite: CONTACT_SECURITE }, db, dossier: cfg.donnees, env, log,
    assistant: { reglages: REGLAGES_NEXARC, spec: SPEC_NEXARC, version: VERSION, controler: lireConfigNexarc },
    version: VERSION, nouveautes: lireNouveautes(new URL('../nouveautes.json', import.meta.url)),
    migrer: ({ comptes, coffre }) => migrerComptes({ db, comptes, coffre, log }),
  });
  migrerParc({ db, log });
  lienDeSecours({ db, comptes: socle.comptes, journal: socle.journal, urlPublique: socle.cfg.urlPublique, log });

  const parc = new Parc(db, { coffre: socle.coffre, horsLigneApres: cfg.horsLigneApres });
  let rescelles;
  try { rescelles = parc.resceller(); } catch (e) { socle.arreter(); db.close(); throw e; }
  if (rescelles.vnc || rescelles.redfish) log.info?.(`[coffre] Secrets d'appareils rescellés sous SOCLE_CLE : ${rescelles.vnc} mot(s) de passe VNC, ${rescelles.redfish} identifiant(s) Redfish.`);
  if (rescelles.retires) {
    log.warn?.(`[coffre] ${rescelles.retires} secret(s) d'appareil illisible(s) sous les deux clés, retiré(s) : à ressaisir.`);
    socle.journal.ecrire({ acteur: 'système', action: 'coffre.secrets_retires', resultat: 'erreur', details: { n: rescelles.retires } });
  }
  const synapse = new Synapse({ url: cfg.synapseUrl, jeton: cfg.synapseJeton, log });
  const flux = new Flux();
  const alertes = new Alertes(db, {
    parc, flux, synapse,
    seuils: { horsLigneMin: cfg.alerteHorsLigneMin, correctifsJours: cfg.alerteCorrectifsJours, disquePct: cfg.alerteDisquePct, risque: cfg.alerteRisque },
  });
  const agents = new Agents(db, { parc, maxMachines: cfg.maxMachines, synapse, alertes, flux: l => flux.pousser({ t: 'flux', ...l }) });
  const taches = new Taches(db, { parc, synapse, journal: socle.journal, flux, commandeLibre: cfg.commandeLibre });
  // Le canal permanent des agents : une tâche créée part tout de suite, et
  // l'écran et le terminal passent par lui (aucun port ouvert sur les postes).
  const canaux = new Canaux({ log });
  taches.surCreation = machineId => canaux.signaler(machineId);
  canaux.surChangement = () => flux.pousser({ t: 'canal' });
  const consoles = cfg.consoleUrl ? new OrigineConsoles({ url: cfg.consoleUrl, parc, comptes: socle.comptes, proxys: socle.portail.proxys, journal: socle.journal, racine: RACINE }) : null;
  const api = creerApi({ socle, cfg, db, parc, agents, alertes, taches, synapse, flux, racine: RACINE, consoles, log, canaux });
  // Données d'un compte : exportées à sa demande, neutralisées à sa suppression.
  socle.portail.exporteur = compteId => parc.donneesDe(compteId);
  socle.comptes.apresSuppression.push(compteId => parc.oublier(compteId));

  // Boucles de fond : collecte (marquage hors ligne), automatisations, purge.
  const bCollecte = setInterval(() => { try { for (const l of agents.collecter()) flux.pousser({ t: 'flux', ...l }); } catch (e) { log.error?.('collecte:', e.message); } }, cfg.intervalle * 1000);
  const bAutos = setInterval(() => { try { taches.tour(); } catch (e) { log.error?.('automatisation:', e.message); } }, 60000);
  const bPurge = setInterval(() => {
    try { agents.purger(); alertes.purger(); } catch (e) { log.error?.('purge:', e.message); }
  }, 600000);
  for (const b of [bCollecte, bAutos, bPurge]) b.unref?.();

  const origines = req => {
    const o = origineDe(req, socle.portail.proxys);
    return [o, ...socle.portail.originesEnPlus].filter(Boolean);
  };

  // Toute requête compte : une page en demande une vingtaine, une rafale des milliers.
  const debit = new Debit({ max: 900 });
  // Seules les consoles et, s'il s'ouvre intégré, le bureau Mesh s'affichent en cadre.
  const cadres = [cfg.consoleUrl && new URL(cfg.consoleUrl).origin, cfg.meshEmbed && cfg.meshUrl && new URL(cfg.meshUrl).origin].filter(Boolean);
  const serveur = http.createServer(envelopper(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://nexarc');
      const ctx = socle.portail.contexte(req, res);
      if (!debit.prendre(ctx.ip)) { socle.journal.rare(`debit:${ctx.ip}`, { action: 'limite.atteinte', objet: 'requetes', ip: ctx.ip, resultat: 'refus' }); throw new ErreurHttp(429, 'Trop de requêtes.'); }
      ctx.url = url;
      const nonce = nonceCsp();
      entetesSecurite(res, { secure: ctx.securise, csp: politiqueContenu({ nonce, secure: ctx.securise, img: ['data:'], connect: ["'self'"], frame: cadres }) });
      if (await socle.portail.traiter(req, res, url, ctx)) return;
      if (await api.traiter(ctx)) return;
      if (!['GET', 'HEAD'].includes(req.method)) return repondreJson(res, 405, { error: 'Méthode non admise.' });
      if (url.pathname.startsWith('/socle/') && servirFichier(req, res, path.join(RACINE, 'socle', 'web'), url.pathname.slice(6), { nonce, cache: 'public, max-age=3600' })) return;
      const fichier = url.pathname === '/' ? '/index.html' : url.pathname;
      // La page porte la version dans l'adresse de ses fichiers : un relais qui
      // impose sa durée de cache au navigateur (Cloudflare) ne sert jamais
      // l'interface d'avant après une mise à jour. La page elle-même : no-store.
      if (fichier === '/index.html') {
        const html = avecDisposition(PAGE.replaceAll('__NONCE__', nonce).replaceAll('__GAMME__', GAMMES.includes(socle.cfg.gamme) ? socle.cfg.gamme : 'soma'), { nonce });
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(html) });
        return res.end(req.method === 'HEAD' ? undefined : html);
      }
      if (servirFichier(req, res, path.join(RACINE, 'web'), fichier, { nonce, gamme: socle.cfg.gamme })) return;
      repondreJson(res, 404, { error: 'Introuvable.' });
    } catch (e) { repondreErreur(res, e, { journal: log }); }
  }));

  serveur.on('upgrade', async (req, socket) => {
    try {
      const url = new URL(req.url, 'http://nexarc');
      // Une mise à niveau compte dans le débit de l'adresse, comme une requête.
      if (!debit.prendre(adresseClient(req, socle.portail.proxys))) return refuser(socket, 429, 'Too Many Requests');
      const v = verifierUpgrade(req, { origines: origines(req) });
      if (!v.ok) return refuser(socket, v.code, v.erreur);
      // Le canal d'un agent : son jeton, pas une session (il n'a pas de navigateur).
      if (url.pathname === '/api/agent/canal') return upgradeCanal(req, socket);
      // Session du socle exigée et rôle vérifié AVANT la mise à niveau.
      const acces = autoriserWs(req);
      if (!acces) return refuser(socket, 401, 'Unauthorized');

      const ecran = /^\/vnc\/([A-Za-z0-9_-]{16})\/agent$/.exec(url.pathname);
      if (ecran) return await upgradeEcranAgent(req, socket, acces, ecran[1]);
      const term = /^\/terminal\/([A-Za-z0-9_-]{16})$/.exec(url.pathname);
      if (term) return await upgradeTerminal(req, socket, acces, term[1], url);
      const m = /^\/vnc\/([A-Za-z0-9_-]{16})\/(\d+)$/.exec(url.pathname);
      if (m) return await upgradeVnc(req, socket, acces, m[1], Number(m[2]));
      refuser(socket, 404, 'Not Found');
    } catch { try { socket.destroy(); } catch { /* déjà fermé */ } }
  });

  // Le contexte du socle, pas une copie : même nom de cookie (préfixe __Host-
  // derrière un relais HTTPS déclaré, sans préfixe en HTTP local), même session,
  // même contrôle de rôle et même journal des refus que pour une route HTTP.
  function autoriserWs(req) {
    const ctx = socle.portail.contexte(req, null);
    try { socle.portail.exiger(ctx, { role: 'membre' }); return ctx; } catch { return null; }
  }

  // Le canal d'un agent. Son jeton est vérifié avant la mise à niveau, avec le
  // même compteur d'échecs par adresse que ses remontées : un jeton refusé ne
  // tente pas sa chance sans fin.
  function upgradeCanal(req, socket) {
    const ip = adresseClient(req, socle.portail.proxys);
    const cles = [`ip:machine:${ip}`];
    try { socle.limiteur.controler(cles); } catch { return refuser(socket, 429, 'Too Many Requests'); }
    const machine = agents.resoudre(String(req.headers['x-agent-token'] || ''));
    if (!machine?.id) {
      socle.limiteur.echec(cles);
      socle.journal.rare(`canal-refus:${ip}`, { action: 'connexion.jeton', objet: '/api/agent/canal', ip, resultat: 'refus' });
      return refuser(socket, 401, 'Unauthorized');
    }
    const ws = accepter(req, socket);
    canaux.brancher(ws, machine);
  }

  // Prise en main (écran par l'agent, terminal) : administrateur, sous renfort
  // récent, et réglage « prise en main » actif. Rien n'est montré à qui ne
  // passe pas ces contrôles, et chaque ouverture va au journal de sécurité.
  function priseEnMain(req, socket, ctx, ref) {
    if (!cfg.priseEnMain) { refuser(socket, 403, 'Forbidden'); return null; }
    try { socle.portail.exiger(ctx, { role: 'admin', renfort: true }); } catch { refuser(socket, 403, 'Forbidden'); return null; }
    const id = parc.idDe(ref);
    if (!id) { refuser(socket, 404, 'Not Found'); return null; }
    return { id, m: parc.machine(id) };
  }

  async function upgradeEcranAgent(req, socket, ctx, ref) {
    const cible = priseEnMain(req, socket, ctx, ref); if (!cible) return;
    const offert = String(req.headers['sec-websocket-protocol'] || '').split(',').map(x => x.trim());
    const ws = accepter(req, socket, { sousProtocole: offert.includes('binary') ? 'binary' : null });
    let f;
    try { f = await canaux.ouvrir(cible.id, 'ecran'); } catch (e) { ws.fermerCode(1011, String(e.message).slice(0, 110)); return; }
    socle.journal.rare(`ecran-agent:${ctx.session.id}:${cible.id}`, { acteur: ctx.session.compte, action: 'prise_en_main.ecran', objet: cible.m.host, ip: ctx.ip }, 10 * 60e3);
    // Le pont prend la main sur la fermeture des deux côtés (un seul rappel par événement).
    await pontFlux(ws, f, { motDePasse: f.infos.motDePasse || '' }).catch(() => { try { ws.close(); } catch { /* fermé */ } f.destroy(); });
  }

  async function upgradeTerminal(req, socket, ctx, ref, url) {
    const cible = priseEnMain(req, socket, ctx, ref); if (!cible) return;
    const ws = accepter(req, socket);
    const cols = Number(url.searchParams.get('cols')) || 100, rows = Number(url.searchParams.get('rows')) || 30;
    // Navigateur → poste : les touches en binaire, la taille en texte. Ce qui
    // est tapé pendant que l'agent ouvre la session attend (borné), puis part.
    let f = null, enAttente = [], taille = 0, parti = false;
    ws.on('fermeture', () => { parti = true; f?.destroy(); });
    ws.on('binaire', d => { if (f) f.write(d); else if ((taille += d.length) <= 64 * 1024) enAttente.push(d); });
    ws.on('texte', t => { try { const m = JSON.parse(t); if (m?.t === 'taille' && f) f.taille(m.cols, m.rows); } catch { /* ignoré */ } });
    try { f = await canaux.ouvrir(cible.id, 'terminal', { cols, rows }); } catch (e) { ws.fermerCode(1011, String(e.message).slice(0, 110)); return; }
    if (parti) { f.destroy(); return; }
    socle.journal.ecrire({ acteur: ctx.session.compte, action: 'prise_en_main.terminal', objet: cible.m.host, ip: ctx.ip });
    for (const d of enAttente) f.write(d);
    enAttente = null;
    // Poste → navigateur : la sortie.
    f.on('data', d => ws.envoyerBinaire(d));
    f.on('close', () => { try { ws.fermerCode(1000, 'session terminée'); } catch { /* fermé */ } });
    if (f.ferme) ws.fermerCode(1000, 'session terminée');
  }

  async function upgradeVnc(req, socket, ctx, ref, idx) {
    const id = parc.idDe(ref); if (!id) return refuser(socket, 404);
    const c = parc.cibleVnc(id, idx);
    if (!c) return refuser(socket, 404);
    const { host, port, motDePasse } = c;
    const offert = String(req.headers['sec-websocket-protocol'] || '').split(',').map(x => x.trim());
    const ws = accepter(req, socket, { sousProtocole: offert.includes('binary') ? 'binary' : null });
    // noVNC se reconnecte seul : une ligne par session et par console suffit.
    socle.journal.rare(`console:${ctx.session.id}:${id}:${idx}`, { acteur: ctx.session.compte, action: 'console.ouverte', objet: c.machine, ip: ctx.ip, details: { type: 'vnc', idx } }, 10 * 60e3);
    await pont(ws, host, port, { motDePasse }).catch(() => { try { ws.close(); } catch { /* fermé */ } });
  }

  serveur.headersTimeout = 20000;
  serveur.requestTimeout = 0;      // les flux SSE et WebSocket durent
  serveur.keepAliveTimeout = 5000;
  await new Promise(r => serveur.listen(cfg.port, cfg.hote, r));
  log.info(`NEXARC ${VERSION} à l'écoute sur ${cfg.hote}:${serveur.address().port}`);
  if (consoles) {
    await consoles.ecouter(cfg.consolePort, cfg.hote);
    log.info(`Consoles web sur ${cfg.hote}:${consoles.serveur.address().port}, servies à ${consoles.origine}`);
    const hoteConsoles = new URL(consoles.origine).hostname;
    if ([cfg.urlEnrolement, socle.cfg.urlPublique].some(u => u && new URL(u).hostname === hoteConsoles)) {
      log.warn?.(`NEXARC_CONSOLE_URL partage le nom d'hôte de NEXARC : les scripts des cartes restent à part, pas les cookies. Donne-lui son propre nom (README, « Consoles et cartes de gestion »).`);
    }
  }
  const arreter = () => new Promise(r => { api.frappes?.arreterTout(); canaux.arreter(); socle.arreter(); clearInterval(bCollecte); clearInterval(bAutos); clearInterval(bPurge); consoles?.arreter(); serveur.close(() => { db.close(); r(); }); serveur.closeAllConnections?.(); });
  return { serveur, socle, cfg, db, parc, agents, alertes, taches, api, consoles, canaux, arreter };
}

// Le processus du conteneur supervise le service et le relance quand
// l'assistant a posé de nouveaux réglages.
if (import.meta.url === `file://${process.argv[1]}` && !superviser()) {
  demarrer().then(({ arreter }) => {
    for (const s of ['SIGTERM', 'SIGINT']) process.on(s, () => arreter().then(() => process.exit(0)));
  }).catch(e => { console.error(e.message); process.exit(1); });
}
