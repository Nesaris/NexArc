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

ajouterPictos({ agrandir: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>' });

const lire = (k, d) => { try { return localStorage.getItem(k) ?? d; } catch { return d; } };
const poser = (k, v) => { try { localStorage.setItem(k, v); } catch { /* navigation privée */ } };
export const estMac = () => /mac|iphone|ipad/i.test(navigator.userAgentData?.platform || navigator.platform || '');
const safari = () => /^((?!chrome|chromium|android|crios|fxios|edg|opr).)*safari/i.test(navigator.userAgent || '');
const attendre = ms => new Promise(r => setTimeout(r, ms));

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
export const FRAPPE_MAX = 4000;

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
export async function ouvrirVncDistant({ url, titre }) {
  const ecran = h('div', { class: 'remote-frame vncscreen' });
  const recu = h('pre', { class: 'presse-recu', text: '' });
  const aTaper = h('textarea', { class: 'field presse-envoi', rows: 3, placeholder: 'Le texte à taper dans la machine', spellcheck: 'false' });
  const avance = h('span', { class: 'dim fs12' });
  let rfb = null, connecte = false, enFrappe = false, dernierPresse = '', copieArmee = 0;
  let resize = lire('nexarc-vnc-ajuster', '1') === '1', qualiteMax = lire('nexarc-vnc-qualite', '0') === '1';
  const panneau = h('div', { class: 'remote-panneau', hidden: true },
    h('div', { class: 'remote-panneau-col' }, h('b', { class: 'fs12', text: 'Copié dans la machine' }), recu,
      h('button', { class: 'btn sm', type: 'button', onclick: () => copierIci() }, icone('copie', 13), 'Copier ici')),
    h('div', { class: 'remote-panneau-col' }, h('b', { class: 'fs12', text: 'Taper dans la machine' }), aTaper,
      h('div', { class: 'rowline9' }, h('button', { class: 'btn sm solid', type: 'button', onclick: () => taper(aTaper.value) }, 'Taper'), avance)));

  const c = coquille({
    titre, contenu: [panneau, ecran], surFermer: () => { try { rfb?.disconnect(); } catch { /* fermé */ } },
    menu: () => {
      const off = !connecte;
      return [
        { titre: 'Presse-papiers', items: [
          { texte: 'Copier', touche: estMac() ? '⌘C' : 'Ctrl+C', inactif: off, agir: () => { copieArmee = Date.now(); combo(K.ctrl, [keysymDe('c'), 'KeyC']); } },
          { texte: 'Coller', touche: estMac() ? '⌘V' : 'Ctrl+V', inactif: off, agir: () => collerIci() },
          { texte: 'Tout sélectionner', touche: estMac() ? '⌘A' : 'Ctrl+A', inactif: off, agir: () => combo(K.ctrl, [keysymDe('a'), 'KeyA']) },
          { texte: panneau.hidden ? 'Taper un texte…' : 'Masquer le presse-papiers', agir: () => { panneau.hidden = !panneau.hidden; if (!panneau.hidden) aTaper.focus(); } },
        ] },
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
  // Taper un texte, caractère par caractère, à un rythme que la machine suit ;
  // rien ne reste enfoncé, même coupé en route.
  async function taper(texte) {
    if (!connecte) return c.dire('Pas connecté.', true);
    if (enFrappe) return c.dire('Une frappe est déjà en cours.', true);
    const caracteres = [...String(texte || '')].slice(0, FRAPPE_MAX);
    if (!caracteres.length) return;
    enFrappe = true;
    let sautes = 0;
    try {
      for (let i = 0; i < caracteres.length && connecte; i++) {
        const ks = keysymDe(caracteres[i]);
        if (!ks) { sautes++; continue; }
        rfb.sendKey(ks, null, true); await attendre(8); rfb.sendKey(ks, null, false); await attendre(22);
        if (i % 16 === 15) avance.textContent = `frappe ${i + 1}/${caracteres.length}…`;
      }
    } finally { enFrappe = false; avance.textContent = ''; rfb?.focus(); }
    if (sautes) c.dire(`${sautes} caractère${sautes > 1 ? 's' : ''} de contrôle ignoré${sautes > 1 ? 's' : ''}.`);
  }
  // Coller : le presse-papiers d'ici, tapé dans la machine (marche partout,
  // écran de connexion et BIOS compris).
  function collerIci() {
    if (!navigator.clipboard?.readText) { panneau.hidden = false; aTaper.focus(); return c.dire('Colle ton texte dans le panneau, puis « Taper ».'); }
    navigator.clipboard.readText().then(t => (t ? taper(t) : c.dire('Le presse-papiers est vide.')), () => { panneau.hidden = false; aTaper.focus(); c.dire('Le navigateur n’a pas donné le presse-papiers : colle-le dans le panneau, puis « Taper ».', true); });
  }
  function copierIci() {
    if (!dernierPresse) return c.dire('Rien de copié dans la machine pour l’instant.');
    navigator.clipboard?.writeText(dernierPresse).then(() => c.dire('Copié ici.'), () => c.dire('Le navigateur refuse : sélectionne le texte du panneau et copie-le.', true));
  }

  // Clavier : sur Mac, ⌘ + touche devient Ctrl + touche dans la machine
  // (⌘C, ⌘S, ⌘F, ⌘←…), ⌘ seul la touche Super, ⌘Espace la recherche (Super),
  // ⌘Tab Alt+Tab. macOS ne donne pas le relâché d'une touche lâchée sous ⌘ :
  // l'appui part complet. ⌘V / Ctrl+V tapent le presse-papiers d'ici.
  // Écouté en capture, avant noVNC, qui ne voit pas ce qui est pris ici.
  const mac = estMac();
  let metaSeul = null, keysym = null;
  const prises = new Set();
  const prendre = e => { e.preventDefault(); e.stopImmediatePropagation(); };
  ecran.addEventListener('keydown', e => {
    if (!connecte) return;
    const lettre = e.key.length === 1 ? e.key.toLowerCase() : '';
    const coller = (mac ? e.metaKey && !e.ctrlKey : e.ctrlKey && !e.metaKey) && !e.altKey && lettre === 'v';
    if (coller) { prendre(e); prises.add(e.code); metaSeul = null; if (!e.repeat) collerIci(); return; }
    if (!mac) { if (e.ctrlKey && (lettre === 'c' || lettre === 'x')) copieArmee = Date.now(); return; }
    if (/^Meta/.test(e.code)) { prendre(e); metaSeul = e.code; return; }
    if (!e.metaKey || /^(Shift|Control|Alt)/.test(e.code)) return;
    prendre(e); prises.add(e.code); metaSeul = null;
    if (e.code === 'Space') { if (!e.repeat) combo(K.super); return; }
    if (e.code === 'Tab') { if (!e.repeat) combo(K.alt, K.tab); return; }
    if (lettre === 'c' || lettre === 'x') { if (e.repeat) return; copieArmee = Date.now(); }
    const ks = keysym?.(e) || (lettre ? keysymDe(lettre) : 0);
    if (ks) combo(K.ctrl, [ks, e.code]);
  }, true);
  ecran.addEventListener('keyup', e => {
    if (/^Meta/.test(e.code) && mac) { prendre(e); if (metaSeul === e.code && connecte) combo(K.super); metaSeul = null; return; }
    if (prises.delete(e.code)) prendre(e);
  }, true);

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
}
