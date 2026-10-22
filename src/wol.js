// Réveil par le réseau (Wake-on-LAN).
//
// Un paquet magique est 6×0xFF suivis de l'adresse MAC répétée 16 fois, en
// diffusion UDP. Une diffusion ne franchit pas les routeurs : un paquet émis
// par NEXARC n'atteint que son propre segment. Pour réveiller une machine
// d'un autre VLAN, NEXARC confie l'émission à un agent en ligne du même
// segment (tâche « wol »), qui diffuse localement.
import dgram from 'node:dgram';

const MAC_RE = /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/;

export function normaliserMac(mac) {
  const m = String(mac || '').trim();
  if (!MAC_RE.test(m)) return null;
  return m.replace(/-/g, ':').toLowerCase();
}

export function paquetMagique(mac) {
  const propre = String(mac).replace(/[:-]/g, '');
  if (propre.length !== 12 || !/^[0-9a-fA-F]{12}$/.test(propre)) throw new Error('adresse MAC invalide');
  const corps = Buffer.from(propre, 'hex');
  const pkt = Buffer.alloc(6 + 16 * 6, 0xff);
  for (let i = 0; i < 16; i++) corps.copy(pkt, 6 + i * 6);
  return pkt;
}

// /24 : approximation raisonnable du même segment L2 sur un réseau à plat.
export function sousReseau(ip) {
  const p = String(ip || '').split('.');
  return p.length === 4 && p.every(x => /^\d{1,3}$/.test(x) && Number(x) <= 255) ? p.slice(0, 3).join('.') : '';
}

// Diffusion dirigée : l'adresse de diffusion du /24 de la cible, calculée et
// validée (quatre octets décimaux) avant tout envoi.
export function diffusionDirigee(ip) {
  const sub = sousReseau(ip);
  return sub ? `${sub}.255` : '';
}

// Réveil confié à MapMyLAN (POST /api/reveil, jeton dérivé) : rend la raison
// d'un refus en une ligne, jamais la réponse brute.
export async function reveilParMapmylan(url, jeton, mac, { fetch: f = fetch, delaiMs = 8000 } = {}) {
  const normalisee = normaliserMac(mac);
  if (!url || !jeton || !normalisee) return { ok: false, raison: 'non relié' };
  try {
    const r = await f(new URL('/api/reveil', url), {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(delaiMs),
      headers: { authorization: `Bearer ${jeton}`, 'content-type': 'application/json' },
      body: JSON.stringify({ mac: normalisee }),
    });
    if (r.ok) return { ok: true };
    if (r.status === 404) return { ok: false, raison: 'MAC jamais vue par MapMyLAN' };
    if (r.status === 401 || r.status === 403) return { ok: false, raison: 'jeton refusé par MapMyLAN' };
    return { ok: false, raison: `MapMyLAN a répondu ${r.status}` };
  } catch {
    return { ok: false, raison: 'MapMyLAN injoignable' };
  }
}

// Émission locale (seulement si le conteneur est sur le réseau de l'hôte).
export function emettre(mac, { diffusion = '255.255.255.255', ports = [9, 7] } = {}) {
  return new Promise((resolve, reject) => {
    const normalisee = normaliserMac(mac);
    if (!normalisee) return reject(new Error('adresse MAC invalide'));
    const pkt = paquetMagique(normalisee);
    const s = dgram.createSocket('udp4');
    s.once('error', e => { try { s.close(); } catch { /* déjà fermé */ } reject(e); });
    s.bind(() => {
      s.setBroadcast(true);
      let restants = ports.length;
      const fini = () => { if (--restants <= 0) { try { s.close(); } catch { /* déjà fermé */ } resolve(); } };
      // Meilleur effort : un envoi refusé sur un port n'empêche pas l'autre.
      for (const port of ports) s.send(pkt, port, diffusion, () => fini());
    });
  });
}
