// Écran distant de NEXARC dans Chromium, sans carte réelle : un faux serveur
// VNC (RFB 3.8, sans mot de passe, une image unie) derrière un WebSocket, la
// page de console servie telle quelle. Vérifie les touches envoyées (Mac :
// ⌘ + touche → Ctrl + touche, ⌘ seul → Super, ⌘Tab → Alt+Tab, ⌘V tape le
// presse-papiers ; menu Actions), la barre cachée en plein écran et la mise
// en page à quatre largeurs. Usage : node outils/parcours-ecran.mjs
import { chromium } from 'playwright';
import { chevauchements } from '../socle/essai/mise-en-page.mjs';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
const PAGE = "<!doctype html><html data-theme=\"light\"><meta charset=utf-8><link rel=stylesheet href=\"/socle/soma.css\"><link rel=stylesheet href=\"/nexarc.css\"><body>\n<script type=module>\nimport { ouvrirVncDistant, ouvrirCadreDistant } from '/ecran-distant.js';\nconst api = { get: c => fetch(c).then(r => r.json()), post: (c, b) => fetch(c, { method: 'POST', body: JSON.stringify(b) }).then(r => r.json()), del: c => fetch(c, { method: 'DELETE' }).then(r => r.json()) };\nwindow.ouvrirVnc = () => ouvrirVncDistant({ url: `ws://${location.host}/rfb`, titre: 'KVM \u00b7 serveur-a', frappe: { api, chemin: '/api/frappe', idx: 0 } });\nwindow.ouvrirCadre = () => ouvrirCadreDistant('/cadre.html', 'iDRAC \u00b7 serveur-b');\nwindow.pret = true;\n</script>\n";
import { accepter } from '../src/websocket.js';
const N = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const touches = [], coupe = [], frappes = [];
const types = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html' };
const srv = http.createServer((q, r) => {
  const u = q.url.split('?')[0];
  if (u === '/') { r.setHeader('content-type', 'text/html'); return r.end(PAGE); }
  let f = u === '/cadre.html' ? null : u.startsWith('/socle/') ? path.join(N, 'socle/web', u.slice(7)) : path.join(N, 'web', u);
  if (u === '/touches') { r.setHeader('content-type', 'application/json'); return r.end(JSON.stringify({ touches, coupe })); }
  if (u === '/vider') { touches.length = 0; coupe.length = 0; return r.end('ok'); }
  // La frappe par le serveur, simulée : le corps reçu est noté, la frappe dite finie.
  if (u === '/api/frappe') {
    r.setHeader('content-type', 'application/json');
    if (q.method === 'POST') { let b = ''; q.on('data', d => { b += d; }); q.on('end', () => { const c = JSON.parse(b); frappes.push(c); r.end(JSON.stringify({ etat: 'en cours', total: [...c.texte].length, tapes: 0, debut: frappes.length, msParCaractere: 20 })); }); return; }
    return r.end(JSON.stringify(frappes.length ? { etat: 'terminée', total: [...frappes.at(-1).texte].length, tapes: [...frappes.at(-1).texte].length, sautes: 0, debut: frappes.length, msParCaractere: 20 } : { etat: 'aucune' }));
  }
  if (!f) { r.setHeader('content-type', 'text/html'); return r.end('<body style="background:#123;color:#fff;font:20px sans-serif">console de la carte</body>'); }
  try { r.setHeader('content-type', types[path.extname(f)] || 'application/octet-stream'); r.end(fs.readFileSync(f)); } catch { r.statusCode = 404; r.end(); }
});
srv.on('upgrade', (req, socket) => {
  const ws = accepter(req, socket, { sousProtocole: (req.headers['sec-websocket-protocol'] || '').split(',')[0].trim() || null });
  let tampon = Buffer.alloc(0), etape = 'version';
  const W = 800, H = 500;
  ws.envoyerBinaire(Buffer.from('RFB 003.008\n'));
  ws.on('binaire', b => {
    tampon = Buffer.concat([tampon, b]);
    for (;;) {
      if (etape === 'version') { if (tampon.length < 12) return; tampon = tampon.subarray(12); ws.envoyerBinaire(Buffer.from([1, 1])); etape = 'secu'; continue; }
      if (etape === 'secu') { if (tampon.length < 1) return; tampon = tampon.subarray(1); ws.envoyerBinaire(Buffer.from([0, 0, 0, 0])); etape = 'init'; continue; }
      if (etape === 'init') {
        if (tampon.length < 1) return; tampon = tampon.subarray(1);
        const nom = Buffer.from('faux');
        const si = Buffer.alloc(24 + nom.length); si.writeUInt16BE(W, 0); si.writeUInt16BE(H, 2);
        Buffer.from([32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0]).copy(si, 4); si.writeUInt32BE(nom.length, 20); nom.copy(si, 24);
        ws.envoyerBinaire(si); etape = 'msg'; continue;
      }
      if (!tampon.length) return;
      const t = tampon[0];
      const need = { 0: 20, 3: 10, 4: 8, 5: 6 }[t] ?? (t === 2 ? (tampon.length >= 4 ? 4 + 4 * tampon.readUInt16BE(2) : 1e9) : t === 6 ? (tampon.length >= 8 ? 8 + tampon.readUInt32BE(4) : 1e9) : 1e9);
      if (need === 1e9 && ![2, 6].includes(t)) { console.log('message inconnu', t); tampon = Buffer.alloc(0); return; }
      if (tampon.length < need) return;
      const m = tampon.subarray(0, need); tampon = tampon.subarray(need);
      if (t === 4) touches.push([m[1], m.readUInt32BE(4).toString(16)]);
      if (t === 6) coupe.push(m.subarray(8).toString('latin1'));
      if (t === 3 && !m[1]) { // première demande complète : une image unie, en Raw
        const r = Buffer.alloc(4 + 12 + W * H * 4, 0x30); r[0] = 0; r[1] = 0; r.writeUInt16BE(1, 2);
        r.writeUInt16BE(0, 4); r.writeUInt16BE(0, 6); r.writeUInt16BE(W, 8); r.writeUInt16BE(H, 10); r.writeInt32BE(0, 12);
        ws.envoyerBinaire(r);
      }
    }
  });
});
await new Promise(ok => srv.listen(0, '127.0.0.1', ok));
const B = `http://127.0.0.1:${srv.address().port}`;

const ecarts = [];
const attendu = (nom, obtenu, voulu) => { if (JSON.stringify(obtenu) !== JSON.stringify(voulu)) ecarts.push(`${nom} : ${JSON.stringify(obtenu)} au lieu de ${JSON.stringify(voulu)}`); };
const navigateur = await chromium.launch();
const c = await navigateur.newContext({ viewport: { width: 1280, height: 800 } });
await c.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: B });
await c.addInitScript(() => { Object.defineProperty(Navigator.prototype, 'platform', { get: () => 'MacIntel' }); Object.defineProperty(Navigator.prototype, 'userAgentData', { get: () => ({ platform: 'macOS' }) }); });
const p = await c.newPage(); const erreurs = []; p.on('pageerror', e => erreurs.push(String(e)));
await p.goto(B); await p.waitForFunction(() => window.pret);
await p.evaluate(() => window.ouvrirVnc());
await p.getByText('connecté', { exact: true }).waitFor();
await p.locator('.vncscreen canvas').click({ position: { x: 100, y: 100 } });
const essai = async (nom, fn, voulu) => { touches.length = 0; await fn(); await p.waitForTimeout(300); attendu(nom, touches.map(([d, k]) => `${d ? '+' : '-'}${k}`), voulu); };
const meta = touche => async () => { await p.keyboard.down('Meta'); await p.keyboard.press(touche); await p.keyboard.up('Meta'); };
await essai('frappe', () => p.keyboard.type('ls'), ['+6c', '-6c', '+73', '-73']);
await essai('⌘S', meta('s'), ['+ffe3', '+73', '-73', '-ffe3']);
await essai('⌘ seul', () => p.keyboard.press('Meta'), ['+ffeb', '-ffeb']);
await essai('⌘Espace', meta('Space'), ['+ffeb', '-ffeb']);
await essai('⌘Tab', meta('Tab'), ['+ffe9', '+ff09', '-ff09', '-ffe9']);
await p.evaluate(() => navigator.clipboard.writeText('Ab1'));
await essai('⌘V : aucune touche d’ici, NEXARC tape', async () => { await meta('v')(); await p.waitForTimeout(400); }, []);
attendu('⌘V : le texte part à NEXARC, avec le clavier de la machine', frappes.at(-1), { idx: 0, texte: 'Ab1', clavier: 'us' });
// Machine en AZERTY derrière un serveur QWERTY : le caractère d'ici, sur sa touche là-bas.
await p.getByRole('button', { name: 'Actions' }).click();
await p.getByRole('menuitem', { name: /AZERTY/ }).click();
await p.locator('.vncscreen canvas').click({ position: { x: 100, y: 100 } });
await essai('AZERTY : a, m', () => p.keyboard.type('am'), ['+71', '-71', '+3b', '-3b']);
await essai('AZERTY : A (Maj tenue ici, Maj+Q là-bas)', () => p.keyboard.type('A'), ['+ffe1', '+51', '-51', '-ffe1']);
await essai('AZERTY : 1 et @', () => p.keyboard.type('1@'), ['+ffe1', '+21', '-21', '-ffe1', '+ffea', '+30', '-30', '-ffea']);
await essai('AZERTY : ⌘A → Ctrl + touche Q', meta('a'), ['+ffe3', '+71', '-71', '-ffe3']);
await essai('AZERTY : Maj+flèche part avec Maj', async () => { await p.keyboard.down('Shift'); await p.keyboard.press('ArrowLeft'); await p.keyboard.up('Shift'); }, ['+ffe1', '+ff51', '-ff51', '-ffe1']);
await p.getByRole('button', { name: 'Actions' }).click();
await p.getByRole('menuitem', { name: /traduit/ }).click();
await p.locator('.vncscreen canvas').click({ position: { x: 100, y: 100 } });
await essai('traduit : le caractère tel quel', () => p.keyboard.type('a'), ['+61', '-61']);
await essai('menu Alt+Tab', async () => { await p.getByRole('button', { name: 'Actions' }).click(); await p.getByRole('menuitem', { name: 'Alt+Tab' }).click(); }, ['+ffe9', '+ff09', '-ff09', '-ffe9']);
await essai('menu Ctrl+Alt+Suppr', async () => { await p.getByRole('button', { name: 'Actions' }).click(); await p.getByRole('menuitem', { name: 'Ctrl+Alt+Suppr' }).click(); }, ['+ffe3', '+ffe9', '+ffff', '-ffff', '-ffe9', '-ffe3']);
await p.getByRole('button', { name: 'Actions' }).click();
await p.getByRole('menuitem', { name: 'Plein écran dans la fenêtre' }).click();
await p.waitForTimeout(400);
const opacite = () => p.locator('.remote-bar').evaluate(e => getComputedStyle(e).opacity);
attendu('barre cachée en plein écran', await opacite(), '0');
await p.mouse.move(2, 400); await p.waitForTimeout(3300);
attendu('barre après 3 s au bord gauche', await opacite(), '1');
await p.mouse.move(700, 500); await p.waitForTimeout(1900);
attendu('barre repartie', await opacite(), '0');
await c.close();
let controles = 0;
for (const w of [360, 390, 768, 1280]) {
  const cx = await navigateur.newContext({ viewport: { width: w, height: 780 } });
  const q = await cx.newPage(); q.on('pageerror', e => erreurs.push(String(e)));
  await q.goto(B); await q.waitForFunction(() => window.pret);
  await q.evaluate(() => window.ouvrirVnc()); await q.getByText('connecté', { exact: true }).waitFor();
  await q.getByRole('button', { name: 'Actions' }).click();
  await q.getByRole('menuitem', { name: 'Taper un texte…' }).click();
  for (const d of await q.evaluate(chevauchements)) ecarts.push(`vnc @${w} : ${d.type} ${d.detail}`);
  await q.getByRole('button', { name: 'Fermer' }).click();
  await q.evaluate(() => window.ouvrirCadre());
  await q.frameLocator('iframe').getByText('console de la carte').waitFor();
  await q.getByRole('button', { name: 'Actions' }).click();
  await q.getByRole('menuitem', { name: 'Plein écran dans la fenêtre' }).click();
  await q.mouse.move(2, 400); await q.waitForTimeout(3300);
  attendu(`cadre @${w} : barre au bord gauche`, await q.locator('.remote-bar').evaluate(e => getComputedStyle(e).opacity), '1');
  for (const d of await q.evaluate(chevauchements)) ecarts.push(`cadre @${w} : ${d.type} ${d.detail}`);
  controles += 2;
  await cx.close();
}
await navigateur.close(); srv.close();
console.log(`écran distant : 19 vérifications de touches et de barre, ${controles} écrans×largeurs, écarts : ${ecarts.length}, erreurs console : ${erreurs.length}`);
for (const e of [...ecarts, ...erreurs]) console.log('  ', e);
process.exit(ecarts.length || erreurs.length ? 1 : 0);
