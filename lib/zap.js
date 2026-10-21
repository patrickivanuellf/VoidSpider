/* Klien untuk REST API OWASP ZAP (https://www.zaproxy.org/docs/api/). ZAP TIDAK dijalankan dari sini --
   ini hanya memanggil daemon ZAP yang SUDAH berjalan di mesinmu sendiri (lihat README untuk cara
   menjalankannya). Modul ini punya dua mode:
     - spider + passive scan: merayapi target dan membaca alert pasif ZAP. Tidak mengirim payload
       serangan, risikonya setara pemindai kita sendiri.
     - active scan: ZAP MENGIRIM payload uji (SQLi, XSS, dan sejenisnya) ke target. Ini lalu lintas
       serangan sungguhan. Jangan pernah dijalankan tanpa izin eksplisit dan tanpa diaktifkan
       secara sadar oleh pemanggil (lihat requireActiveConfirmation di server.js).

   Perubahan v9.1:
   - Spider hanya dijalankan sekali per proses (bukan tiap siklus) — dikontrol dari server.js
   - Active scan menangani HTTP 400 dengan pesan jelas + memastikan URL ada di Sites tree
   - ensureInTree: akses URL dulu supaya ZAP mengenal target
   - Filter alert Low-confidence lebih agresif supaya dashboard tidak penuh noise
*/

import { F } from './rules.js';

const RISK = { High: 2, Medium: 1, Low: 0, Informational: 0 };
const POLL_MS = 2000;

function url(base, path, params, apiKey) {
  const u = new URL(path, base.endsWith('/') ? base : `${base}/`);
  for (const [k, v] of Object.entries(params || {})) if (v !== undefined) u.searchParams.set(k, v);
  if (apiKey) u.searchParams.set('apikey', apiKey);
  return u.href;
}

async function call(base, path, params, apiKey, fetchImpl = fetch, timeout = 15000) {
  const res = await fetchImpl(url(base, path, params, apiKey), { signal: AbortSignal.timeout(timeout) });
  if (!res.ok) {
    let detail = '';
    try {
      const body = await res.text();
      detail = body ? ` — ${body.slice(0, 200)}` : '';
    } catch { /* abaikan */ }
    throw new Error(`ZAP ${path} -> HTTP ${res.status}${detail}`);
  }
  return res.json();
}

/** Cek daemon ZAP hidup dan versinya. Melempar error kalau tidak terjangkau -- biarkan pemanggil menangani. */
export async function zapVersion(base, apiKey, fetchImpl = fetch) {
  const j = await call(base, '/JSON/core/view/version/', {}, apiKey, fetchImpl, 5000);
  return j.version;
}

async function poll(fn, { max = 150, delay = POLL_MS } = {}) {
  for (let i = 0; i < max; i++) {
    const v = await fn();
    if (v >= 100) return;
    await new Promise((r) => setTimeout(r, delay));
  }
  throw new Error('ZAP: batas waktu menunggu pemindaian selesai');
}

/** Pastikan URL target sudah dikenal ZAP (ada di Sites tree). Kalau belum, akses sekali. */
async function ensureInTree(base, target, apiKey, fetchImpl = fetch) {
  try {
    const sites = await call(base, '/JSON/core/view/sites/', {}, apiKey, fetchImpl, 8000);
    const list = sites.sites || [];
    const origin = new URL(target).origin;
    if (list.some((s) => String(s).startsWith(origin))) return true;
  } catch { /* lanjut coba akses */ }

  try {
    await call(base, '/JSON/core/action/accessUrl/', { url: target, followRedirects: true }, apiKey, fetchImpl, 20000);
    return true;
  } catch (e) {
    throw new Error(`ZAP tidak bisa mengakses target (${e.message}). Pastikan ZAP bisa menjangkau ${target}`);
  }
}

/** Merayapi target lewat spider ZAP (GET berurutan mengikuti tautan, seperti crawler kita sendiri). */
export async function zapSpider(base, target, apiKey, fetchImpl = fetch, opts = {}) {
  await ensureInTree(base, target, apiKey, fetchImpl);

  const params = { url: target, recurse: true };
  if (opts.maxChildren != null) params.maxChildren = opts.maxChildren;

  const start = await call(base, '/JSON/spider/action/scan/', params, apiKey, fetchImpl);
  const scanId = start.scan;
  await poll(async () => Number((await call(base, '/JSON/spider/view/status/', { scanId }, apiKey, fetchImpl)).status), opts);

  await poll(async () => {
    const left = Number((await call(base, '/JSON/pscan/view/recordsToScan/', {}, apiKey, fetchImpl)).recordsToScan);
    return left === 0 ? 100 : 0;
  }, { max: 90, delay: 2000 });
}

/** MENGIRIM PAYLOAD SERANGAN ke target (SQLi, XSS, command injection, dst). Hanya panggil ini
    setelah pemanggil memastikan izin eksplisit -- lihat --zap-active-scan dan konfirmasinya di server.js. */
export async function zapActiveScan(base, target, apiKey, fetchImpl = fetch, opts = {}) {
  await ensureInTree(base, target, apiKey, fetchImpl);

  try {
    await call(base, '/JSON/core/action/setMode/', { mode: 'attack' }, apiKey, fetchImpl, 5000);
  } catch { /* opsional, versi ZAP tertentu beda */ }

  let start;
  try {
    start = await call(
      base,
      '/JSON/ascan/action/scan/',
      { url: target, recurse: true, inScopeOnly: false },
      apiKey,
      fetchImpl,
      20000
    );
  } catch (e) {
    if (String(e.message).includes('400')) {
      // Fallback tanpa recurse
      start = await call(
        base,
        '/JSON/ascan/action/scan/',
        { url: target, recurse: false, inScopeOnly: false },
        apiKey,
        fetchImpl,
        20000
      );
    } else {
      throw e;
    }
  }

  const scanId = start.scan;
  await poll(
    async () => Number((await call(base, '/JSON/ascan/view/status/', { scanId }, apiKey, fetchImpl)).status),
    { max: 600, ...opts }
  );
}

/** Ambil semua alert ZAP untuk target. */
export async function zapAlerts(base, target, apiKey, fetchImpl = fetch, { count = 2000 } = {}) {
  const j = await call(base, '/JSON/core/view/alerts/', { baseurl: target, start: 0, count }, apiKey, fetchImpl, 30000);
  return j.alerts || [];
}

/** Ubah alert mentah ZAP jadi F() findings. Filter noise Low+Informational. */
export function alertsToFindings(alerts, { maxPerGroup = 4, maxGroups = 60, dropLowNoise = true } = {}) {
  const groups = new Map();
  for (const a of alerts) {
    const name = a.alert || a.name || 'Temuan ZAP';
    if (!groups.has(name)) {
      groups.set(name, {
        risk: a.risk,
        confidence: a.confidence,
        solution: a.solution,
        urls: new Set(),
        params: new Set(),
      });
    }
    const g = groups.get(name);
    const order = { High: 3, Medium: 2, Low: 1, Informational: 0 };
    if ((order[a.risk] || 0) > (order[g.risk] || 0)) g.risk = a.risk;
    if (a.confidence === 'High' || a.confidence === 'Medium') g.confidence = a.confidence;
    if (a.url) g.urls.add(a.url);
    if (a.param) g.params.add(a.param);
  }

  const out = [];
  let gi = 0;
  for (const [name, g] of groups) {
    if (gi >= maxGroups) break;

    let lvl = RISK[g.risk] ?? 1;
    if (g.confidence === 'Low') lvl = Math.max(0, lvl - 1);

    if (dropLowNoise && lvl === 0 && (g.risk === 'Informational' || g.risk === 'Low') && g.confidence === 'Low') {
      continue;
    }

    gi++;
    const urls = [...g.urls].slice(0, maxPerGroup);
    const more = g.urls.size > urls.length ? ` (+${g.urls.size - urls.length} URL lain)` : '';
    const params = g.params.size ? ` [parameter: ${[...g.params].slice(0, 3).join(', ')}]` : '';
    const text = `ZAP: ${name}${params} -- ${urls.join(', ')}${more}`;
    const fix = g.solution
      ? String(g.solution).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 500)
      : '';
    out.push(F(lvl, 'zap', text, fix));
  }
  return out;
}
