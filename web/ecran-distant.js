// Écran distant : la fenêtre d'une console (pont VNC ou cadre du mandataire),
// avec deux pleins écrans, une barre qui se cache, et pour VNC le menu des
// touches et du presse-papiers — les gestes de l'écran de ProxLab.
//
// Plein écran « écran entier » : celui du navigateur ; le clavier entier va à
// la machine (Keyboard Lock) là où le navigateur le permet (Chrome, Edge).
// Plein écran « dans la fenêtre » : la console couvre la page ; Safari, qui
// floute une page plein écran recevant beaucoup de frappes et garde Échap pour
// lui, le prend par défaut. Dans les deux, la barre se cache : la souris gardée
// trois secondes contre le bord gauche la fait revenir.
//
// Tout ce qui s'affiche vit dans la fenêtre de la console : en plein écran du
// navigateur, rien d'autre de la page n'est visible.
import { h, icone, ajouterPictos } from '/socle/compte.js';
import { DISPOSITIONS, appuis, evenementsCaractere } from '/socle/clavier.js';

ajouterPictos({ agrandir: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>' });

const lire = (k, d) => { try { return localStorage.getItem(k) ?? d; } catch { return d; } };
const poser = (k, v) => { try { localStorage.setItem(k, v); } catch { /* navigation privée */ } };
export const estMac = () => /mac|iphone|ipad/i.test(navigator.userAgentData?.platform || navigator.platform || '');
const safari = () => /^((?!chrome|chromium|android|crios|fxios|edg|opr).)*safari/i.test(navigator.userAgent || '');

// Keysyms X11 utilisés ici.
const K = {
  ctrl: [0xffe3, 'ControlLeft'], alt: [0xffe9, 'AltLeft'], shift: [0xffe1, 'ShiftLeft'], super: [0xffeb, 'MetaLeft'],
  tab: [0xff09, 'Tab'], echap: [0xff1b, 'Escape'], impr: [0xff61, 'PrintScreen'], suppr: [0xffff, 'Delete'], entree: [0xff0d, 'Enter'],
};
// Le keysym d'un caractère : Latin-1 tel quel, le reste en Unicode (0x01000000 + point de code).
export function keysymDe(ch) {
  if (ch === '\n' || ch === '\r') return K.entree[0];
  if (ch === '\t') return K.tab[0];
  const c = ch.codePointAt(0);
  if (c < 0x20 || c === 0x7f) return 0;
  return c < 0x100 ? c : 0x01000000 + c;
}
// Le plus long texte que NEXARC tape d'une traite (socle, src/frappe.js).
export const FRAPPE_MAX = 100000;
// Clavier de la machine : AZERTY ou QWERTY derrière un serveur VNC qui change
// les keysyms en touches comme un clavier US (KVM, iDRAC, iLO) — chaque
// caractère tapé ici part sur la touche qui le donne là-bas ; ou « traduit » :
// le serveur VNC d'un bureau le fait lui-même, selon sa disposition.
const CLAVIERS = { ...Object.fromEntries(Object.entries(DISPOSITIONS).map(([k, d]) => [k, d.nom])), traduit: 'Bureau : le serveur VNC traduit' };
const KS_MOD = { ShiftLeft: 0xffe1, ShiftRight: 0xffe2, ControlLeft: 0xffe3, ControlRight: 0xffe4, AltLeft: 0xffe9, AltRight: 0xffea };

// La coquille commune : barre, menu, message, pleins écrans, barre cachée.
function coquille({ titre, contenu, menu = () => [], surFermer = () => {}, extra = [] }) {
  const statut = h('span', { class: 'grow dim fs12' });
  const message = h('div', { class: 'remote-msg', role: 'status', 'aria-live': 'polite', hidden: true });
  let minuteurMsg = null;
  const dire = (texte, mauvais = false) => {
    message.textContent = texte; message.hidden = false; message.classList.toggle('bad', mauvais);
    clearTimeout(minuteurMsg); minuteurMsg = setTimeout(() => { message.hidden = true; }, mauvais ? 7000 : 3800);
  };

  // Le menu Actions, déroulé dans la fenêtre de la console.
  const liste = h('div', { class: 'remote-menu', role: 'menu', hidden: true });
  const fermerMenu = () => { liste.hidden = true; boutonMenu.setAttribute('aria-expanded', 'false'); };
  const boutonMenu = h('button', { class: 'btn', type: 'button', 'aria-label': 'Actions', 'aria-haspopup': 'menu', 'aria-expanded': 'false', onclick: () => {
    if (!liste.hidden) return fermerMenu();
    liste.replaceChildren(...menu().filter(g => g.items.length).flatMap((g, i) => [
      i ? h('div', { class: 'remote-menu-sep', role: 'separator' }) : null,
      g.titre ? h('div', { class: 'remote-menu-titre', text: g.titre }) : null,
      ...g.items.map(it => h('button', { class: 'remote-menu-item', type: 'button', role: 'menuitem', disabled: !!it.inactif, onclick: () => { fermerMenu(); it.agir(); } },
        h('span', { class: 'remote-menu-coche' }, it.coche ? icone('verifie', 14) : null), h('span', { text: it.texte }), it.touche ? h('kbd', { text: it.touche }) : null)),
    ]).filter(Boolean));
    liste.hidden = false; boutonMenu.setAttribute('aria-expanded', 'true');
  } }, icone('menu', 15), h('span', { class: 'remote-etiq', text: 'Actions' }));

  const boutonPlein = h('button', { class: 'btn', type: 'button', 'aria-label': 'Plein écran', title: 'Plein écran', onclick: () => basculer() }, icone('agrandir', 15));
  const bar = h('div', { class: 'remote-bar' },
    h('span', { class: 'remote-dot' }), h('b', { text: titre }), statut, ...extra, h('span', { class: 'remote-ancre' }, boutonMenu, liste), boutonPlein,
    h('button', { class: 'btn solid', type: 'button', 'aria-label': 'Fermer', onclick: () => fermer() }, icone('croix', 15), h('span', { class: 'remote-etiq', text: 'Fermer' })));
  // Le bord gauche : une bande qui capte la souris même au-dessus d'un cadre.
  const bord = h('div', { class: 'remote-bord', 'aria-hidden': 'true' });
  const shell = h('div', { class: 'remote-shell' }, bar, contenu, bord, message);
  const scrim = h('div', { class: 'remote-scrim on' }, shell);

  let mode = lire('nexarc-plein', safari() ? 'fenetre' : 'ecran');
  let clavierPris = false;
  const plein = () => shell.classList.contains('plein');
  const montrerBarre = on => { shell.classList.toggle('barre-visible', on); if (!on) fermerMenu(); };
  let minuteurBord = null, minuteurCache = null;
  bord.addEventListener('pointerenter', () => { if (plein()) { clearTimeout(minuteurBord); minuteurBord = setTimeout(() => montrerBarre(true), 3000); } });
  // La barre repart 1,5 s après que la souris a quitté le bord ou la barre
  // sans y revenir, sauf menu ouvert.
  const cacherBientot = () => { if (plein() && shell.classList.contains('barre-visible')) { clearTimeout(minuteurCache); minuteurCache = setTimeout(() => { if (liste.hidden) montrerBarre(false); }, 1500); } };
  bord.addEventListener('pointerleave', () => { clearTimeout(minuteurBord); cacherBientot(); });
  bar.addEventListener('pointerenter', () => clearTimeout(minuteurCache));
  bar.addEventListener('pointerleave', cacherBientot);
  const dehors = e => { if (!liste.hidden && !liste.contains(e.target) && !boutonMenu.contains(e.target)) fermerMenu(); };
  document.addEventListener('pointerdown', dehors, true);

  const entrer = m => {
    mode = m; poser('nexarc-plein', m);
    shell.classList.add('plein'); scrim.classList.add('plein'); montrerBarre(false);
    if (lire('nexarc-astuce-bord', '') !== '1') { poser('nexarc-astuce-bord', '1'); dire('Barre cachée : garde la souris contre le bord gauche 3 secondes pour la faire revenir.'); }
    if (m === 'ecran') shell.requestFullscreen?.().catch(() => dire('Le navigateur refuse le plein écran : « Plein écran dans la fenêtre » reste possible.', true));
    surPlein(true);
  };
  const sortir = () => {
    shell.classList.remove('plein', 'barre-visible'); scrim.classList.remove('plein');
    if (document.fullscreenElement === shell) document.exitFullscreen().catch(() => {});
    surPlein(false);
  };
  const basculer = () => (plein() ? sortir() : entrer(mode));
  // Écran entier : le clavier entier va à la machine, là où c'est permis.
  shell.addEventListener('fullscreenchange', async () => {
    if (document.fullscreenElement === shell) {
      if (navigator.keyboard?.lock) { try { await navigator.keyboard.lock(); clavierPris = true; dire('Toutes les touches vont à la machine, raccourcis du système compris. Pour sortir : garde Échap enfoncée.'); } catch { /* refusé */ } }
      else if (lire('nexarc-astuce-clavier', '') !== '1') { poser('nexarc-astuce-clavier', '1'); dire('Ce navigateur garde ⌘Espace, ⌘Tab et les raccourcis du système. Avec Chrome ou Edge, en plein écran, toutes les touches vont à la machine.'); }
    } else {
      if (clavierPris) { try { navigator.keyboard.unlock(); } catch { /* rendu */ } clavierPris = false; }
      if (plein() && mode === 'ecran') sortir();
    }
  });
  let surPlein = () => {};
  const fermer = () => { sortir(); document.removeEventListener('pointerdown', dehors, true); scrim.remove(); surFermer(); };
  document.body.append(scrim);
  return {
    shell, statut, dire, fermer, plein, mode: () => mode,
    entrer, sortir, set surPlein(f) { surPlein = f; },
    itemsPlein: () => [
      { texte: plein() && mode === 'ecran' ? 'Quitter le plein écran' : 'Plein écran (écran entier)', coche: plein() && mode === 'ecran', agir: () => (plein() && mode === 'ecran' ? sortir() : (sortir(), entrer('ecran'))) },
      { texte: plein() && mode === 'fenetre' ? 'Quitter le plein écran dans la fenêtre' : 'Plein écran dans la fenêtre', coche: plein() && mode === 'fenetre', agir: () => (plein() && mode === 'fenetre' ? sortir() : (sortir(), entrer('fenetre'))) },
    ],
  };
}

// Console web dans un cadre (iDRAC, iLO, MeshCentral…) : ses touches passent
// par son propre menu (clavier virtuel, macros) ; ici, les pleins écrans.
export function ouvrirCadreDistant(url, titre) {
  const cadre = h('iframe', { class: 'remote-frame', src: url, allow: 'fullscreen; clipboard-read; clipboard-write; keyboard-map', referrerpolicy: 'no-referrer' });
  const c = coquille({
    titre, contenu: cadre,
    extra: [h('a', { class: 'btn remote-etiq', href: url, target: '_blank', rel: 'noopener' }, 'Nouvel onglet')],
    menu: () => [
      { titre: 'Affichage', items: c.itemsPlein() },
      { items: [{ texte: 'Ouvrir dans un nouvel onglet', agir: () => window.open(url, '_blank', 'noopener') }, { texte: 'Recharger la console', agir: () => { cadre.src = url; } }] },
      { titre: 'Touches', items: [{ texte: 'Ctrl+Alt+Suppr et autres touches : menu de la console elle-même', inactif: true, agir: () => {} }] },
    ],
  });
  c.surPlein = () => cadre.focus();
}

// Console VNC (pont de NEXARC) par noVNC, avec les gestes de ProxLab.
// frappe : { api, chemin, idx } — la frappe d'un texte par NEXARC lui-même
// (POST chemin) ; cle : ce qui retient le clavier choisi pour cette console.
export async function ouvrirVncDistant({ url, titre, frappe = null, cle = url }) {
  const ecran = h('div', { class: 'remote-frame vncscreen' });
  const recu = h('pre', { class: 'presse-recu', text: '' });
  const aTaper = h('textarea', { class: 'field presse-envoi', rows: 3, placeholder: 'Le texte à taper dans la machine', spellcheck: 'false' });
  const avance = h('span', { class: 'dim fs12' });
  const puce = h('span', { class: 'remote-frappe', hidden: true });
  const cleClavier = `nexarc-clavier:${cle}`;
  let clavier = lire(cleClavier, /^fr/i.test(navigator.language || '') ? 'fr' : 'us');
  if (!Object.hasOwn(CLAVIERS, clavier)) clavier = 'fr';
  let rfb = null, connecte = false, dernierPresse = '', copieArmee = 0;
  let resize = lire('nexarc-vnc-ajuster', '1') === '1', qualiteMax = lire('nexarc-vnc-qualite', '0') === '1';
  const panneau = h('div', { class: 'remote-panneau', hidden: true },
    h('div', { class: 'remote-panneau-col' }, h('b', { class: 'fs12', text: 'Copié dans la machine' }), recu,
      h('button', { class: 'btn sm', type: 'button', onclick: () => copierIci() }, icone('copie', 13), 'Copier ici')),
    h('div', { class: 'remote-panneau-col' }, h('b', { class: 'fs12', text: 'Taper dans la machine' }), aTaper,
      h('div', { class: 'rowline9' }, h('button', { class: 'btn sm solid', type: 'button', onclick: () => taper(aTaper.value) }, 'Taper'), avance)));

  const c = coquille({
    titre, contenu: [panneau, ecran], extra: [puce], surFermer: () => { clearTimeout(suivi); try { rfb?.disconnect(); } catch { /* fermé */ } },
    menu: () => {
      const off = !connecte;
      return [
        { titre: 'Presse-papiers', items: [
          { texte: 'Copier', touche: estMac() ? '⌘C' : 'Ctrl+C', inactif: off, agir: () => { copieArmee = Date.now(); combo(K.ctrl, [keysymDe('c'), 'KeyC']); } },
          { texte: 'Coller', touche: estMac() ? '⌘V' : 'Ctrl+V', inactif: off, agir: () => collerIci() },
          { texte: 'Tout sélectionner', touche: estMac() ? '⌘A' : 'Ctrl+A', inactif: off, agir: () => combo(K.ctrl, [keysymDe('a'), 'KeyA']) },
          { texte: panneau.hidden ? 'Taper un texte…' : 'Masquer le presse-papiers', agir: () => { panneau.hidden = !panneau.hidden; if (!panneau.hidden) aTaper.focus(); } },
        ] },
        { titre: 'Clavier de la machine', items: Object.entries(CLAVIERS).map(([k, nom]) => ({ texte: nom, coche: clavier === k, agir: () => {
          relacherMods(); modsTenus.clear();
          clavier = k; poser(cleClavier, k);
          c.dire(k === 'traduit' ? 'Chaque caractère part tel quel : le serveur VNC de la machine le change en touches.' : `Clavier ${nom} : ce que tu tapes ici arrive tel quel, quelle que soit la disposition de ton clavier.`);
          rfb?.focus();
        } })) },
        { titre: 'Touches', items: [
          { texte: 'Ctrl+Alt+Suppr', inactif: off, agir: () => { rfb.sendCtrlAltDel(); rfb.focus(); } },
          { texte: 'Touche Super (Windows)', inactif: off, agir: () => combo(K.super) },
          { texte: 'Alt+Tab', inactif: off, agir: () => combo(K.alt, K.tab) },
          { texte: 'Échap', inactif: off, agir: () => combo(K.echap) },
          { texte: 'Impr. écran', inactif: off, agir: () => combo(K.impr) },
        ] },
        { titre: 'Affichage', items: [
          ...c.itemsPlein(),
          { texte: 'Ajuster la machine à la fenêtre', coche: resize, agir: () => { resize = !resize; poser('nexarc-vnc-ajuster', resize ? '1' : '0'); if (rfb) rfb.resizeSession = resize; c.dire(resize ? 'La machine prend la taille de la fenêtre, si son serveur VNC le permet.' : 'La machine garde sa résolution.'); } },
          { texte: 'Qualité maximale', coche: qualiteMax, agir: () => { qualiteMax = !qualiteMax; poser('nexarc-vnc-qualite', qualiteMax ? '1' : '0'); if (rfb) rfb.qualityLevel = qualiteMax ? 9 : 7; } },
          { texte: 'Reconnecter', agir: () => connecter() },
        ] },
      ];
    },
  });
  c.surPlein = () => rfb?.focus();

  // Une touche, ou une combinaison : enfoncées dans l'ordre, relâchées à rebours.
  const combo = (...touches) => {
    if (!connecte) return;
    for (const [ks, code] of touches) rfb.sendKey(ks, code, true);
    for (const [ks, code] of [...touches].reverse()) rfb.sendKey(ks, code, false);
    rfb.focus();
  };
  // Taper un texte : NEXARC le tape lui-même, par sa propre connexion à la
  // console, au clavier de la machine. On peut fermer la console ou quitter la
  // page : la frappe continue, et se retrouve ici en revenant.
  let suivi = null, vue = 0;
  const duree = (n, ms) => { const t = Math.ceil(n * ms / 1000); return t < 60 ? `${t} s` : `${Math.round(t / 60)} min`; };
  const urlEtat = () => `${frappe.chemin}?idx=${frappe.idx}`;
  const peindre = fr => {
    const enCours = fr?.etat === 'en cours';
    puce.hidden = !enCours;
    avance.textContent = enCours ? `frappe ${fr.tapes}/${fr.total}…` : '';
    if (enCours) puce.replaceChildren(h('span', { text: `Frappe ${fr.tapes}/${fr.total} · reste ${duree(fr.total - fr.tapes, fr.msParCaractere)}` }),
      h('button', { class: 'btn sm', type: 'button', onclick: async () => { try { peindre(await frappe.api.del(urlEtat())); c.dire('Frappe arrêtée.'); } catch (e) { c.dire(e.message, true); } } }, 'Arrêter'));
  };
  async function suivre() {
    clearTimeout(suivi);
    if (!frappe) return;
    let fr;
    try { fr = await frappe.api.get(urlEtat()); } catch { return; }
    peindre(fr);
    if (fr.etat === 'en cours') { vue = fr.debut; suivi = setTimeout(suivre, 700); return; }
    if (vue && vue === fr.debut) {
      vue = 0;
      if (fr.etat === 'terminée') c.dire(fr.sautes ? `Tapé, sauf ${fr.sautes} caractère${fr.sautes > 1 ? 's' : ''} absent${fr.sautes > 1 ? 's' : ''} du clavier de la machine.` : `Frappe terminée : ${fr.tapes} caractère${fr.tapes > 1 ? 's' : ''}.`, !!fr.sautes);
      else if (fr.etat === 'échec') c.dire(`Frappe interrompue (${fr.tapes}/${fr.total}) : ${fr.message}`, true);
    }
  }
  async function taper(texte) {
    texte = String(texte || '');
    if (!texte) return;
    if (!frappe) return c.dire('La frappe passe par NEXARC : ouvre la console depuis sa machine.', true);
    const n = [...texte].length;
    if (n > FRAPPE_MAX) return c.dire(`Au plus ${FRAPPE_MAX.toLocaleString('fr-FR')} caractères par frappe (ici ${n.toLocaleString('fr-FR')}).`, true);
    let fr;
    try { fr = await frappe.api.post(frappe.chemin, { idx: frappe.idx, texte, clavier }); } catch (e) { return c.dire(e.message, true); }
    vue = fr.debut;
    peindre(fr);
    if (fr.total > 150) c.dire(`NEXARC tape ${fr.total.toLocaleString('fr-FR')} caractères dans la machine (environ ${duree(fr.total, fr.msParCaractere)}) : tu peux fermer la console, la frappe continue.`);
    rfb?.focus();
    suivi = setTimeout(suivre, 500);
  }
  // Coller : le presse-papiers d'ici, tapé dans la machine par NEXARC (marche
  // partout, écran de connexion et BIOS compris).
  function collerIci() {
    if (!navigator.clipboard?.readText) { panneau.hidden = false; aTaper.focus(); return c.dire('Colle ton texte dans le panneau, puis « Taper ».'); }
    navigator.clipboard.readText().then(t => (t ? taper(t) : c.dire('Le presse-papiers est vide.')), () => { panneau.hidden = false; aTaper.focus(); c.dire('Le navigateur n’a pas donné le presse-papiers : colle-le dans le panneau, puis « Taper ».', true); });
  }
  function copierIci() {
    if (!dernierPresse) return c.dire('Rien de copié dans la machine pour l’instant.');
    navigator.clipboard?.writeText(dernierPresse).then(() => c.dire('Copié ici.'), () => c.dire('Le navigateur refuse : sélectionne le texte du panneau et copie-le.', true));
  }

  // Clavier. Au caractère (AZERTY ou QWERTY) : ce qui est tapé ici part sur
  // la touche qui le donne dans la disposition de la machine ; Maj, Ctrl et
  // Alt ne partent qu'avec une touche sans caractère (flèches, Entrée,
  // fonctions, laissées à noVNC) ou une lettre de raccourci. « Traduit » :
  // noVNC envoie le caractère, le serveur VNC fait le reste.
  // Sur Mac, ⌘ + touche devient Ctrl + touche dans la machine (⌘C, ⌘S, ⌘F,
  // ⌘←…), ⌘ seul la touche Super, ⌘Espace la recherche (Super), ⌘Tab
  // Alt+Tab. macOS ne donne pas le relâché d'une touche lâchée sous ⌘ :
  // l'appui part complet. ⌘V / Ctrl+V : NEXARC tape le presse-papiers d'ici.
  // Écouté en capture, avant noVNC, qui ne voit pas ce qui est pris ici.
  const mac = estMac();
  let metaSeul = null, keysym = null, modUtilise = false;
  const prises = new Set(), modsTenus = new Set(), modsEnvoyes = new Set();
  const prendre = e => { e.preventDefault(); e.stopImmediatePropagation(); };
  const envoyerMods = () => { for (const code of modsTenus) if (!modsEnvoyes.has(code)) { modsEnvoyes.add(code); rfb.sendKey(KS_MOD[code], code, true); } modUtilise = true; };
  function relacherMods() { if (connecte) for (const code of modsEnvoyes) rfb.sendKey(KS_MOD[code], code, false); modsEnvoyes.clear(); }
  const caractere = ch => {
    const ev = evenementsCaractere(ch, clavier, { mode: 'us' });
    if (!ev) return c.dire(`« ${ch} » n’existe pas sur le clavier ${CLAVIERS[clavier]} de la machine.`, true);
    relacherMods();
    for (const x of ev) rfb.sendKey(x.keysym, x.code, x.bas);
    modUtilise = true;
  };
  // Une lettre de raccourci, sur sa touche dans la disposition de la machine : [keysym, code].
  const touche = l => {
    const a = appuis(l, clavier);
    if (!a || a.length !== 1 || a[0][1] || a[0][2]) return null;
    return [evenementsCaractere(l, clavier, { mode: 'us' }).find(x => x.bas).keysym, a[0][0]];
  };
  ecran.addEventListener('keydown', e => {
    if (!connecte) return;
    const lettre = e.key.length === 1 ? e.key.toLowerCase() : '';
    const coller = (mac ? e.metaKey && !e.ctrlKey : e.ctrlKey && !e.metaKey) && !e.altKey && lettre === 'v';
    if (coller) { prendre(e); prises.add(e.code); metaSeul = null; if (!e.repeat) collerIci(); return; }
    const auCaractere = clavier !== 'traduit';
    if (auCaractere) {
      if (e.code === 'CapsLock' || e.key === 'Dead') { prendre(e); return; }
      if (KS_MOD[e.code]) { prendre(e); if (!modsTenus.has(e.code)) { modsTenus.add(e.code); modUtilise = false; } return; }
      const altgr = typeof e.getModifierState === 'function' && e.getModifierState('AltGraph');
      const ch = [...e.key].length === 1 && !e.metaKey && (!e.ctrlKey || altgr) && (!e.altKey || altgr || mac) ? e.key : null;
      if (ch !== null) { prendre(e); prises.add(e.code); metaSeul = null; caractere(ch); return; }
      if (!mac && e.ctrlKey && !e.altKey && lettre && touche(lettre)) {
        prendre(e); prises.add(e.code);
        if (lettre === 'c' || lettre === 'x') { if (e.repeat) return; copieArmee = Date.now(); }
        modUtilise = true;
        combo(K.ctrl, ...(e.shiftKey ? [K.shift] : []), touche(lettre));
        return;
      }
    }
    if (mac && /^Meta/.test(e.code)) { prendre(e); metaSeul = e.code; return; }
    if (!mac || !e.metaKey || /^(Shift|Control|Alt)/.test(e.code)) {
      if (!mac && e.ctrlKey && (lettre === 'c' || lettre === 'x')) copieArmee = Date.now();
      // Une touche sans caractère : Maj, Ctrl et Alt tenus partent avec elle, noVNC envoie le reste.
      if (auCaractere) envoyerMods();
      return;
    }
    prendre(e); prises.add(e.code); metaSeul = null;
    if (e.code === 'Space') { if (!e.repeat) combo(K.super); return; }
    if (e.code === 'Tab') { if (!e.repeat) combo(K.alt, K.tab); return; }
    if (lettre === 'c' || lettre === 'x') { if (e.repeat) return; copieArmee = Date.now(); }
    const t = auCaractere && lettre ? touche(lettre) : null;
    if (t) { combo(K.ctrl, ...(e.shiftKey ? [K.shift] : []), t); return; }
    const ks = keysym?.(e) || (lettre ? keysymDe(lettre) : 0);
    if (ks) combo(K.ctrl, [ks, e.code]);
  }, true);
  ecran.addEventListener('keyup', e => {
    if (modsTenus.has(e.code)) {
      prendre(e);
      if (modsEnvoyes.delete(e.code)) { if (connecte) rfb.sendKey(KS_MOD[e.code], e.code, false); }
      // Alt seul, appuyé puis lâché (menus de Windows) : l'appui part entier.
      else if (/^Alt/.test(e.code) && !modUtilise && !mac) combo([KS_MOD[e.code], e.code]);
      modsTenus.delete(e.code);
      return;
    }
    if (/^Meta/.test(e.code) && mac) { prendre(e); if (metaSeul === e.code && connecte) combo(K.super); metaSeul = null; return; }
    if (prises.delete(e.code)) prendre(e);
  }, true);
  ecran.addEventListener('focusout', () => { relacherMods(); modsTenus.clear(); });
  ecran.addEventListener('pointerdown', () => { if (connecte && modsTenus.size && clavier !== 'traduit') envoyerMods(); }, true);

  async function connecter() {
    try { rfb?.disconnect(); } catch { /* déjà fermé */ }
    connecte = false;
    c.statut.textContent = 'connexion…';
    try {
      const [{ default: RFB }, util] = await Promise.all([import('/vendor/novnc/core/rfb.js'), import('/vendor/novnc/core/input/util.js')]);
      keysym = util.getKeysym;
      ecran.replaceChildren();
      rfb = new RFB(ecran, url, {});
      rfb.scaleViewport = true; rfb.clipViewport = false; rfb.resizeSession = resize; rfb.qualityLevel = qualiteMax ? 9 : 7;
      rfb.addEventListener('connect', () => { connecte = true; c.statut.textContent = 'connecté'; rfb.focus(); });
      rfb.addEventListener('disconnect', e => { connecte = false; c.statut.textContent = e.detail?.clean ? 'déconnecté' : 'connexion perdue'; });
      rfb.addEventListener('securityfailure', () => { c.statut.textContent = 'échec d\'authentification'; });
      // Ce que la machine copie : gardé ici, et dans le presse-papiers d'ici
      // juste après un Copier (si le navigateur l'accepte).
      rfb.addEventListener('clipboard', e => {
        dernierPresse = String(e.detail?.text || '');
        recu.textContent = dernierPresse;
        if (Date.now() - copieArmee < 3000) { copieArmee = 0; navigator.clipboard?.writeText(dernierPresse).then(() => c.dire('Copié ici.'), () => { panneau.hidden = false; c.dire('Copié dans la machine : le texte est dans le panneau (« Copier ici »).'); }); }
      });
    } catch { c.statut.textContent = 'noVNC indisponible'; }
  }
  await connecter();
  suivre();
}
