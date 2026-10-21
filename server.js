import http from 'node:http';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import tls from 'node:tls';
import { fileURLToPath } from 'node:url';
import * as cheerio from 'cheerio';
import {
  F, fkey, score, INJ, INVISIBLE_TAG, findSecrets, PROBES, ERR_LEAK, INTERNAL_IP,
} from './lib/rules.js';
import { auditFile, auditDir, loadIgnore, VCS_DIRS, SKIP_DIRS } from './lib/filescan.js';
import { auditTls, auditSubCerts } from './lib/tlsaudit.js';
import { auditDns } from './lib/dnsaudit.js';
import { DEP_FILES, auditDepsFile } from './lib/deps.js';
import { Baseline, scriptHosts, SUSPICIOUS_INLINE } from './lib/drift.js';
import { makeNotifier } from './lib/notify.js';
import { IntelAggregator, parseSshLine, parseCowrie, tailFile } from './lib/intel.js';
import { hasGit, gitHead, scanGitHistory } from './lib/githistory.js';
import { makeAgent, snippet } from './lib/agent.js';
import { toSarif } from './lib/sarif.js';
import { jwtScan } from './lib/jwt.js';
import { genericSecretFindings } from './lib/entropy.js';
import { detectWaf } from './lib/waf.js';
import { loadUserProbes } from './lib/userprobes.js';
import { zapVersion, zapSpider, zapActiveScan, zapAlerts, alertsToFindings } from './lib/zap.js';
import { explain, prioritize } from './lib/explain.js';
import { deepHtmlChecks, fingerprint } from './lib/deepcheck.js';
import { safeSignalsForPage, shouldProbe } from './lib/safe_signals.js';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const UA = 'LabaLabaPemindai/2.0 (audit keamanan situs/berkas milik sendiri)';

/* ---------- Konfigurasi dan pengaman ---------- */

const argv = process.argv.slice(2);
const VALUE_FLAGS = new Set(['--sarif', '--json', '--md', '--fail-on', '--ssh-log', '--honeypot-log', '--data-dir', '--cookie', '--zap', '--zap-api-key', '--profil']);
const MULTI_FLAGS = new Set(['--header']); // bisa diberikan berkali-kali: --header "A: 1" --header "B: 2"
const flags = {};
const positional = [];
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (MULTI_FLAGS.has(a)) (flags[a] ||= []).push(argv[++i]);
  else if (VALUE_FLAGS.has(a)) flags[a] = argv[++i];
  else if (a.startsWith('--')) flags[a] = true;
  else positional.push(a);
}

// Header tambahan untuk audit terautentikasi: sesi cookie atau token Authorization, dikirim ke SETIAP
// permintaan di mode situs. Ini membuat pemindai bertindak sebagai akun yang login itu -- hanya pakai
// sesi milikmu sendiri, dan anggap token di sini sensitif seperti password.
const EXTRA_HEADERS = {};
if (flags['--cookie']) EXTRA_HEADERS.cookie = flags['--cookie'];
for (const h of flags['--header'] || []) {
  const i = h.indexOf(':');
  if (i > 0) EXTRA_HEADERS[h.slice(0, i).trim().toLowerCase()] = h.slice(i + 1).trim();
}
const targetArg = positional[0] || process.env.TARGET;
const confirmed = Boolean(flags['--saya-pemilik-situs']) || process.env.SAYA_PEMILIK === 'ya';
const ONCE = Boolean(flags['--once']); // mode CI: satu siklus lalu keluar, tanpa dasbor
const OFFLINE = Boolean(flags['--offline']) || process.env.OFFLINE === '1'; // lewati CVE, DNS, dan CT (tidak ada panggilan keluar)

if (!targetArg) {
  console.error(
    'Pemakaian:\n' +
      '  Situs : node server.js https://situsmu.com --saya-pemilik-situs\n' +
      '  Berkas: node server.js ./folder-atau-berkas\n' +
      'Opsi  : --once --sarif f.sarif --json f.json --md f.md --fail-on kritis|sedang|info|tidak\n' +
      '        --ssh-log /var/log/auth.log --honeypot-log cowrie.json --agent --offline\n' +
      '        --terima-perubahan (perbarui baseline) --pakai-baseline (dengan --once)\n' +
      '        --cookie "sesi=..." (audit halaman di balik login dengan sesi milikmu sendiri)\n' +
      '        --header "Authorization: Bearer ..." (bisa diulang untuk header lain)\n' +
      '        --zap http://127.0.0.1:8080 [--zap-api-key K] (gabungkan alert ZAP; daemon ZAP jalan sendiri)\n' +
      '        --zap-active-scan --saya-paham-risiko-active-scan (ZAP MENGIRIM payload serangan -- baca README)\n' +
      '        --zap-skip-spider (jangan jalankan spider ZAP, pakai data yang sudah ada)\n' +
      '        --profil kampus|umkm|wordpress|ketat (preset kecepatan & cakupan)'
  );
  process.exit(1);
}

// Mode ditentukan dari target: URL http(s) = audit situs, selain itu path lokal = audit berkas.
const MODE = /^https?:\/\//i.test(targetArg) ? 'web' : 'file';

let targetUrl = null;
let origin = '';
let isHttps = false;
let rootDir = '';
let rootIsFile = false;
let label = '';

if (MODE === 'web') {
  try {
    targetUrl = new URL(targetArg);
  } catch {
    console.error('URL target tidak valid. Contoh: https://situsmu.com');
    process.exit(1);
  }
  origin = targetUrl.origin;
  isHttps = targetUrl.protocol === 'https:';
  label = targetUrl.host;
  const isLocal = /^(localhost|127\.|10\.|192\.168\.)/.test(targetUrl.hostname) || targetUrl.hostname.endsWith('.local');
  if (!confirmed && !isLocal) {
    console.error(
      'Pemindai ini hanya boleh dipakai pada situs milikmu atau yang sudah mengizinkan pengujian.\n' +
        'Jika memang situsmu, jalankan lagi dengan tambahan: --saya-pemilik-situs'
    );
    process.exit(1);
  }
} else {
  try {
    rootDir = fs.realpathSync(path.resolve(targetArg));
    rootIsFile = fs.statSync(rootDir).isFile();
  } catch {
    console.error('Target bukan URL (https://...) dan bukan path yang ada di disk.');
    process.exit(1);
  }
  label = path.basename(rootDir);
  origin = `file://${rootDir}`;
}

const D = MODE === 'web' ? { interval: 90, conc: 2, pages: 200, delay: 280 } : { interval: 30, conc: 3, pages: 400, delay: 30 };
const CFG = {
  port: Number(process.env.PORT) || 3000,
  bind: process.env.BIND || '127.0.0.1',
  interval: (Number(process.env.INTERVAL) || D.interval) * 1000,
  concurrency: Math.min(8, Math.max(1, Number(process.env.CONCURRENCY) || D.conc)),
  maxPages: Number(process.env.MAX_PAGES) || D.pages,
  delay: process.env.DELAY_MS !== undefined && process.env.DELAY_MS !== '' ? Number(process.env.DELAY_MS) || 0 : D.delay,
  timeout: Number(process.env.TIMEOUT_MS) || 10000,
  maxBytes: 2 * 1024 * 1024,
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const LEVEL = ['info', 'sedang', 'kritis'];

const DATA_DIR = flags['--data-dir'] || process.env.DATA_DIR || path.join(DIR, 'data');
const slug = label.replace(/[^a-z0-9.-]+/gi, '_').slice(0, 60);
const baseline = !ONCE || flags['--pakai-baseline']
  ? new Baseline(path.join(DATA_DIR, `${MODE}-${slug}.baseline.json`), { accept: Boolean(flags['--terima-perubahan']) })
  : null;
const notifier = makeNotifier({ label });
const agent = makeAgent({ enabled: Boolean(flags['--agent']) });
const ZAP_BASE = flags['--zap'];
const ZAP_KEY = flags['--zap-api-key'] || process.env.ZAP_API_KEY;
const ZAP_ACTIVE = Boolean(flags['--zap-active-scan']);
if (ZAP_ACTIVE && !flags['--saya-paham-risiko-active-scan']) {
  console.error(
    '--zap-active-scan membuat ZAP MENGIRIM payload serangan sungguhan (SQLi, XSS, dst) ke target.\n' +
      'Ini bukan audit pasif. Jalankan hanya pada staging/milikmu sendiri yang siap menerima lalu lintas itu,\n' +
      'bukan produksi yang sedang dipakai orang. Tambahkan juga --saya-paham-risiko-active-scan untuk melanjutkan.'
  );
  process.exit(1);
}
let zapChecked = false;
let zapSpiderDone = false;
const ZAP_SKIP_SPIDER = Boolean(flags['--zap-skip-spider']);
const PROFIL = String(flags['--profil'] || '').toLowerCase();
// Preset untuk konteks Indonesia: kampus, umkm, wordpress, ketat
if (PROFIL === 'kampus' || PROFIL === 'umkm') {
  // lebih sabar ke situs lambat / shared hosting
  CFG.interval = Math.max(CFG.interval, 120000);
  CFG.delay = Math.max(CFG.delay, 400);
  CFG.concurrency = Math.min(CFG.concurrency, 2);
  CFG.maxPages = Math.min(CFG.maxPages, 150);
} else if (PROFIL === 'wordpress') {
  CFG.maxPages = Math.max(CFG.maxPages, 250);
} else if (PROFIL === 'ketat') {
  CFG.concurrency = Math.min(CFG.concurrency, 1);
  CFG.delay = Math.max(CFG.delay, 500);
}
let agentPlan = [];
let agentBusy = false;
const gitCache = { head: null, findings: [] };
let lastRemoved = [];
let dnsCache = { at: 0, findings: [], subs: [] };
let tlsCache = { at: 0, findings: [] };
const HOUR = 3600 * 1000;

const intel = new IntelAggregator({
  onEvent: (e) => {
    send('intel', { ...e, top: intel.top(), total: intel.total });
    if (e.type === 'brute') notifier.alert(`brute|${e.ip}|${Math.floor(Date.now() / 600000)}`, `Percobaan brute force dari ${e.ip}: ${e.count} kegagalan login dalam semenit (user dicoba: ${e.users.join(', ')}).`);
    if (e.type === 'success-after-fails') notifier.alert(`ok|${e.ip}|${e.user}`, `PERHATIAN: login SSH berhasil untuk "${e.user}" dari ${e.ip} setelah ${e.fails} kegagalan. Periksa segera.`);
  },
});
const intelOn = Boolean(flags['--ssh-log'] || flags['--honeypot-log']);

/* ---------- State dan SSE ---------- */

const nodes = new Map();
const byId = new Map();
let edges = [];
let edgeSet = new Set();
let nextId = 1;
let cycle = 0;
let phase = 'menunggu';
let nextAt = Date.now();
const clients = new Set();

function send(event, data) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const c of clients) c.write(msg);
}

function pub(n) {
  return {
    id: n.id, path: n.path, type: n.type, from: n.from,
    scanned: n.scanned, status: n.status, ms: n.ms, words: n.words, findings: n.findings,
    terms: n.terms || [], triage: n.triage || {},
  };
}

function summary() {
  const c = [0, 0, 0];
  const all = [];
  let pages = 0;
  for (const n of nodes.values()) {
    if (n.type !== 'ext') pages++;
    for (const f of n.findings) {
      c[f.lvl]++;
      all.push(f);
    }
  }
  const { score: skor, grade } = score(all);
  return { info: c[0], sedang: c[1], kritis: c[2], halaman: pages, skor, nilai: grade };
}

function snapshot() {
  return {
    mode: MODE, target: MODE === 'web' ? origin : `file:///${encodeURIComponent(label)}`, label,
    cycle, phase, interval: CFG.interval,
    nextIn: Math.max(0, nextAt - Date.now()),
    nodes: [...nodes.values()].map(pub),
    edges,
    summary: summary(),
    plan: agentPlan,
    agent: agent.enabled,
    intel: intelOn ? { top: intel.top(), total: intel.total } : null,
  };
}

function reportItems() {
  const items = [];
  for (const n of nodes.values())
    for (const f of n.findings)
      items.push({ n, f });
  items.sort((a, b) => b.f.lvl - a.f.lvl || a.n.path.localeCompare(b.n.path));
  return items;
}

function report() {
  const files = [];
  if (MODE === 'file')
    for (const n of nodes.values()) if (n.sha) files.push({ path: n.path, size: n.size, sha256: n.sha });
  return {
    mode: MODE,
    target: MODE === 'web' ? origin : label,
    generatedAt: new Date().toISOString(),
    cycle,
    summary: summary(),
    findings: reportItems().map(({ n, f }) => {
      const ex = explain(f.rule, f.lvl);
      return {
        path: n.path, ...(MODE === 'web' ? { url: n.url } : {}),
        level: LEVEL[f.lvl], rule: f.rule, text: f.text, fix: f.fix,
        mengapa: ex.mengapa, dampak: ex.dampak,
        ...(n.triage?.[fkey(f)] ? { triase: n.triage[fkey(f)] } : {}),
      };
    }),
    aksiMingguIni: prioritize(reportItems().map(({ n, f }) => ({ rule: f.rule, lvl: f.lvl, text: f.text, path: n.path, fix: f.fix }))),
    ...(agentPlan.length ? { rencana: agentPlan } : {}),
    ...(files.length ? { files } : {}),
  };
}

function reportMd() {
  const s = summary();
  const items = reportItems();
  const flat = items.map(({ n, f }) => ({ rule: f.rule, lvl: f.lvl, text: f.text, path: n.path, fix: f.fix }));
  const week = prioritize(flat);
  const out = [
    `# Laporan Audit Keamanan`,
    `## ${label}`,
    '',
    `| | |`,
    `|---|---|`,
    `| **Target** | ${MODE === 'web' ? origin : label} |`,
    `| **Mode** | ${MODE === 'web' ? 'Situs web (pasif)' : 'Berkas lokal'} |`,
    `| **Waktu** | ${new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })} WIB |`,
    `| **Siklus** | ${cycle} |`,
    `| **Skor** | **${s.skor}/100 (nilai ${s.nilai})** |`,
    `| **Temuan** | ${s.kritis} kritis · ${s.sedang} sedang · ${s.info} info |`,
    `| **Alat** | Laba-laba Pemindai (buatan Indonesia) |`,
    '',
    '> Ini audit **pasif / daftar periksa awal**, bukan pentest penuh. Tidak ada payload serangan kecuali Anda mengaktifkan active scan secara sadar.',
    '',
    '## Ringkasan untuk pimpinan',
    '',
  ];

  if (s.kritis === 0 && s.sedang === 0) {
    out.push('Tidak ada temuan kritis atau sedang pada siklus ini. Tetap pantau perubahan (drift) dan perbarui dependensi secara rutin.', '');
  } else {
    out.push(
      `Ditemukan **${s.kritis} temuan kritis** dan **${s.sedang} temuan sedang** yang perlu perhatian.`,
      `Skor keamanan saat ini **${s.nilai} (${s.skor}/100)**.`,
      '',
      'Disarankan menyelesaikan item pada bagian **Aksi minggu ini** sebelum menambah fitur baru di produksi.',
      '',
    );
  }

  if (week.length) {
    out.push('## Aksi minggu ini', '');
    week.forEach((w, i) => {
      out.push(`### ${i + 1}. [${w.level.toUpperCase()}] ${w.rule}`);
      out.push(`- **Contoh:** ${w.contoh}`);
      if (w.path) out.push(`- **Lokasi:** \`${w.path}\``);
      out.push(`- **Mengapa penting:** ${w.mengapa}`);
      if (w.aksi) out.push(`- **Perbaikan:** ${w.aksi}`);
      out.push('');
    });
  }

  if (agentPlan.length) {
    out.push('## Urutan perbaikan (agent)', '');
    agentPlan.forEach((p, i) => out.push(`${i + 1}. ${p.tindakan}${p.alasan ? ` — ${p.alasan}` : ''}`));
    out.push('');
  }

  for (const lvl of [2, 1, 0]) {
    const group = items.filter(({ f }) => f.lvl === lvl);
    if (!group.length) continue;
    out.push(`## ${LEVEL[lvl].toUpperCase()} (${group.length})`, '');
    for (const { n, f } of group) {
      const ex = explain(f.rule, f.lvl);
      const tv = n.triage?.[fkey(f)];
      out.push(`### ${f.rule}`);
      out.push(`- **Lokasi:** ${MODE === 'web' ? n.url || n.path : n.path}`);
      out.push(`- **Temuan:** ${f.text}`);
      out.push(`- **Mengapa:** ${ex.mengapa}`);
      out.push(`- **Dampak:** ${ex.dampak}`);
      if (f.fix) out.push(`- **Perbaikan:** ${f.fix}`);
      if (tv) out.push(`- **Triase agent:** ${tv.verdict || ''} ${tv.alasan || ''}`);
      out.push('');
    }
  }

  out.push('---', '');
  out.push('_Dibuat dengan Laba-laba Pemindai — alat audit keamanan untuk aset milik sendiri._');
  out.push('');
  return out.join('\n');
}


function shortPath(p) {
  return p.length > 90 ? `…${p.slice(-89)}` : p;
}

function ensureNode(href, type, from) {
  const u = new URL(href);
  u.hash = '';
  const key = u.href;
  let n = nodes.get(key);
  if (n) return n;
  if (nodes.size >= CFG.maxPages) return null;
  n = {
    id: nextId++, key, url: key, path: (u.pathname + u.search).slice(0, 90), type, from,
    scanned: false, findings: [], words: 0, ms: 0, status: 0, seen: 0, queued: 0, probe: null,
  };
  nodes.set(key, n);
  byId.set(n.id, n);
  send('node', pub(n));
  return n;
}

function ensureFileNode(rel, abs, type, from) {
  const key = `fs:${rel}`;
  let n = nodes.get(key);
  if (n) return n;
  if (nodes.size >= CFG.maxPages) return null;
  n = {
    id: nextId++, key, url: key, abs, rel, path: rel === '' ? path.basename(rootDir) : shortPath(rel), type, from,
    scanned: false, findings: [], words: 0, ms: 0, status: 0, seen: 0, queued: 0, probe: null, sha: null, size: 0,
  };
  nodes.set(key, n);
  byId.set(n.id, n);
  send('node', pub(n));
  return n;
}

function ensureExt(host, from) {
  const key = `ext:${host}`;
  let n = nodes.get(key);
  if (!n) {
    if (nodes.size >= CFG.maxPages) return null;
    n = {
      id: nextId++, key, url: key, path: host, type: 'ext', from,
      scanned: true, findings: [], words: 0, ms: 0, status: 0, seen: cycle, queued: 0, probe: null,
    };
    nodes.set(key, n);
    byId.set(n.id, n);
    send('node', pub(n));
  }
  n.seen = cycle;
  return n;
}

function addEdge(a, b) {
  const k = `${a}-${b}`;
  if (a === b || edgeSet.has(k)) return;
  edgeSet.add(k);
  edges.push([a, b]);
  send('edge', [a, b]);
}

/* ---------- HTTP klien (mode web) ---------- */

async function readLimited(res, max) {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let out = '';
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.length;
    out += dec.decode(value, { stream: true });
    if (n > max) {
      await reader.cancel();
      break;
    }
  }
  return out;
}

async function get(url, { force = false, maxBytes = CFG.maxBytes } = {}) {
  let cur = url;
  const t0 = Date.now();
  for (let i = 0; i < 5; i++) {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), CFG.timeout);
    try {
      const res = await fetch(cur, {
        redirect: 'manual',
        signal: ac.signal,
        headers: { 'user-agent': UA, accept: 'text/html,application/xhtml+xml,*/*;q=0.8', ...EXTRA_HEADERS },
      });
      const loc = res.headers.get('location');
      if (res.status >= 300 && res.status < 400 && loc) {
        await res.body?.cancel();
        const next = new URL(loc, cur);
        if (next.origin !== origin) {
          return { status: res.status, headers: res.headers, body: '', ms: Date.now() - t0, url: cur, ct: '' };
        }
        cur = next.href;
        continue;
      }
      const ct = res.headers.get('content-type') || '';
      let body = '';
      if (force || /text|json|javascript|xml|css|svg/i.test(ct)) body = await readLimited(res, maxBytes);
      else await res.body?.cancel();
      return { status: res.status, headers: res.headers, body, ms: Date.now() - t0, url: cur, ct };
    } finally {
      clearTimeout(timer);
    }
  }
  return { status: 0, headers: new Headers(), body: '', ms: Date.now() - t0, url: cur, ct: '', error: 'terlalu banyak redirect' };
}

/* ---------- Analisis web ---------- */

function cspWeak(csp) {
  const dirs = {};
  for (const part of csp.split(';')) {
    const [k, ...v] = part.trim().split(/\s+/);
    if (k) dirs[k.toLowerCase()] = v.join(' ');
  }
  const script = dirs['script-src'] ?? dirs['default-src'];
  if (script === undefined) return [F(1, 'csp-weak', 'CSP tidak membatasi skrip (tidak ada script-src maupun default-src)')];
  const bits = [];
  if (/'unsafe-inline'/.test(script) && !/'nonce-|'strict-dynamic'|'sha(?:256|384|512)-/.test(script)) bits.push("'unsafe-inline'");
  if (/'unsafe-eval'/.test(script)) bits.push("'unsafe-eval'");
  if (/(?:^|\s)\*(?:\s|$)|(?:^|\s)https?:(?:\s|$)/.test(script)) bits.push('wildcard');
  return bits.length ? [F(1, 'csp-weak', `CSP terlalu longgar untuk skrip: ${bits.join(', ')}`)] : [];
}

function headerFindings(h, f) {
  const csp = h.get('content-security-policy');
  if (!csp) f.push(F(1, 'csp', 'Header Content-Security-Policy tidak ada'));
  else f.push(...cspWeak(csp));
  if (!h.get('x-frame-options') && !(csp && /frame-ancestors/i.test(csp)))
    f.push(F(0, 'xfo', 'Proteksi clickjacking tidak ada (X-Frame-Options atau frame-ancestors)'));
  if (!h.get('x-content-type-options')) f.push(F(0, 'xcto', 'Header X-Content-Type-Options tidak ada'));
  if (!h.get('referrer-policy')) f.push(F(0, 'refpol', 'Header Referrer-Policy tidak ada'));
  if (!h.get('permissions-policy')) f.push(F(0, 'permpol', 'Header Permissions-Policy tidak ada'));
  const hs = h.get('strict-transport-security');
  if (isHttps && !hs) f.push(F(1, 'hsts', 'Header HSTS tidak ada'));
  else if (hs) {
    const m = /max-age=(\d+)/i.exec(hs);
    if (m && Number(m[1]) < 15552000) f.push(F(0, 'hsts-weak', `HSTS max-age terlalu pendek (${m[1]} detik)`));
  }
  const xpb = h.get('x-powered-by');
  if (xpb) f.push(F(0, 'xpb', `Header X-Powered-By membuka teknologi server: ${xpb}`));
  const sv = h.get('server');
  if (sv && /\d+\.\d+/.test(sv)) f.push(F(0, 'serverver', `Header Server membuka versi: ${sv}`));
  const acao = h.get('access-control-allow-origin');
  const acac = h.get('access-control-allow-credentials');
  if (acao === '*') {
    if (acac && /true/i.test(acac)) f.push(F(2, 'cors-cred', 'CORS * digabung dengan Allow-Credentials: true (berbahaya)'));
    else f.push(F(0, 'cors', 'CORS terbuka ke semua origin'));
  }
}

function cookieFindings(h, once, f) {
  const list = h.getSetCookie ? h.getSetCookie() : [];
  for (const c of list) {
    const name = c.split('=')[0].trim();
    if (once.has(name)) continue;
    once.add(name);
    const low = c.toLowerCase();
    if (isHttps && !/;\s*secure/.test(low)) f.push(F(1, 'cookie-secure', `Cookie ${name} tanpa flag Secure`));
    if (!/;\s*httponly/.test(low) && /sess|auth|token|sid|login/i.test(name))
      f.push(F(1, 'cookie-httponly', `Cookie sesi ${name} tanpa HttpOnly`));
    if (!/;\s*samesite/.test(low)) f.push(F(0, 'cookie-samesite', `Cookie ${name} tanpa SameSite`));
    if (/;\s*samesite=none/.test(low) && !/;\s*secure/.test(low)) f.push(F(1, 'cookie-none', `Cookie ${name} SameSite=None tanpa Secure`));
  }
}

function analyzeHtml(node, resp, found) {
  const $ = cheerio.load(resp.body);
  const f = [];
  const base = resp.url;

  $('script:not([src])').each((_, e) => {
    if (SUSPICIOUS_INLINE.test($(e).text())) f.push(F(1, 'obfuscation', 'Skrip inline mencurigakan (eval, atob, atau fromCharCode panjang)'));
  });
  if (baseline) f.push(...baseline.hostDrift(scriptHosts($, origin, base)));
  {
    const deep = deepHtmlChecks($, resp.headers, resp.body || '', origin);
    f.push(...deep.findings);
    if (deep.stack.length) node.stack = deep.stack;
  }

  const add = (href, kind) => {
    if (!href || /^(mailto:|tel:|javascript:|data:|#)/i.test(href.trim())) return;
    try {
      const u = new URL(href.trim(), base);
      if (/^https?:$/.test(u.protocol)) found.push({ u, kind });
    } catch { /* tautan rusak diabaikan */ }
  };
  $('a[href]').each((_, e) => add($(e).attr('href'), 'a'));
  $('script[src]').each((_, e) => add($(e).attr('src'), 'asset'));
  $('link[rel~="stylesheet"][href]').each((_, e) => add($(e).attr('href'), 'asset'));

  if (isHttps) {
    const bad = [];
    $('script[src],iframe[src],img[src],source[src],audio[src],video[src],link[rel~="stylesheet"][href],link[rel~="preload"][href],link[rel~="icon"][href]').each((_, e) => {
      const v = $(e).attr('src') || $(e).attr('href');
      if (v && /^http:\/\//i.test(v)) bad.push(v);
    });
    if (bad.length) f.push(F(1, 'mixed', `Mixed content: ${bad.length} sumber memakai http di halaman https`));
  }

  const ext = new Set();
  $('script[src],link[rel~="stylesheet"][href]').each((_, e) => {
    const v = $(e).attr('src') || $(e).attr('href');
    try {
      const u = new URL(v, base);
      if (u.origin !== origin && !$(e).attr('integrity')) ext.add(u.hostname);
    } catch { /* abaikan */ }
  });
  if (ext.size) f.push(F(0, 'sri', `Sumber pihak ketiga tanpa SRI: ${[...ext].slice(0, 3).join(', ')}`));

  const gen = $('meta[name="generator"]').attr('content');
  if (gen && /\d+\.\d+/.test(gen)) f.push(F(0, 'generator', `Meta generator membuka versi: ${gen.slice(0, 40)}`));

  let hasPw = false;
  $('form').each((_, fm) => {
    const form = $(fm);
    const act = form.attr('action') || '';
    if (isHttps && /^http:\/\//i.test(act)) f.push(F(2, 'formhttp', 'Form mengirim data ke alamat http'));
    if (form.find('input[type=password]').length) {
      hasPw = true;
      const tok = form.find('input[type=hidden]').filter((__, x) => /csrf|token|nonce|authenticity/i.test($(x).attr('name') || '')).length;
      if (!tok) f.push(F(1, 'csrf', 'Form berisi kolom sandi tanpa token CSRF yang terlihat'));
      if (!isHttps) f.push(F(2, 'pwhttp', 'Kolom sandi dikirim lewat http tanpa enkripsi'));
      if (/^get$/i.test(form.attr('method') || 'get')) f.push(F(2, 'pwget', 'Form sandi memakai method GET (sandi masuk ke URL)'));
    }
  });
  if (hasPw && !/no-store/i.test(resp.headers.get('cache-control') || ''))
    f.push(F(0, 'pw-cache', 'Halaman dengan form sandi tanpa Cache-Control: no-store'));

  // Open redirect: tautan dengan parameter redirect umum yang menunjuk keluar
  const redirParams = /[?&](?:redirect|redir|return|returnUrl|return_url|next|url|goto|destination|continue|relayState)=https?:\/\//i;
  const openRedirs = [];
  $('a[href]').each((_, e) => {
    const href = $(e).attr('href') || '';
    if (redirParams.test(href)) {
      try {
        const u = new URL(href, base);
        const m = href.match(/[?&](?:redirect|redir|return|returnUrl|return_url|next|url|goto|destination|continue)=([^&]+)/i);
        if (m) {
          const dest = decodeURIComponent(m[1]);
          if (/^https?:\/\//i.test(dest)) {
            const d = new URL(dest);
            if (d.origin !== origin) openRedirs.push(href.slice(0, 80));
          }
        }
      } catch { /* abaikan */ }
    }
  });
  if (openRedirs.length)
    f.push(F(1, 'open-redirect', `Kemungkinan open redirect di tautan (${openRedirs.length}x), contoh: ${openRedirs[0]}`));

  // Auth hint: halaman login tanpa rate-limit signal / autocomplete longgar
  if (hasPw) {
    const auto = $('input[type=password]').attr('autocomplete') || '';
    if (/off/i.test(auto) === false && auto === '') {
      // bukan temuan keras — hanya info lembut sudah cukup lewat csrf/pw
    }
    // Deteksi pesan yang sering bocor user enumeration di teks halaman
    const bodyText = ($('body').text() || '').slice(0, 5000);
    if (/user(?:name)? (?:not found|does not exist|tidak ditemukan)|email (?:not found|tidak terdaftar)/i.test(bodyText))
      f.push(F(1, 'auth-hint', 'Halaman menampilkan pesan yang bisa dipakai enumerasi pengguna'));
  }

  $('script,style,noscript').remove();
  const hidden = [];
  $('[hidden],[aria-hidden="true"],[style*="display:none"],[style*="display: none"],[style*="visibility:hidden"],[style*="font-size:0"]').each((_, e) => hidden.push($(e).text()));
  $('*').contents().each((_, n) => {
    if (n.type === 'comment') hidden.push(n.data || '');
  });
  const visible = $('body').text();
  if (INJ.test(hidden.join(' '))) f.push(F(2, 'inj-hidden', 'Teks tersembunyi berisi pola prompt injection'));
  else if (INJ.test(visible)) f.push(F(1, 'inj-visible', 'Teks halaman berisi pola perintah ke AI (periksa konteksnya)'));

  node.words = visible.split(/\s+/).filter(Boolean).length;
  node.terms = [...new Set(visible.toLowerCase().match(/[a-zà-ÿ]{4,14}/g) || [])].slice(0, 40);
  return f;
}

const isLocalHost = () => MODE === 'web' && /^(localhost|127\.|10\.|192\.168\.)/.test(targetUrl.hostname);

async function cycleChecks() {
  const out = [];
  if (!isHttps) return out;
  if (!OFFLINE || isLocalHost()) {
    if (Date.now() - tlsCache.at > HOUR) {
      tlsCache = { at: Date.now(), findings: await auditTls(targetUrl.hostname, Number(targetUrl.port) || 443).catch(() => []) };
    }
    out.push(...tlsCache.findings);
  }
  if (!targetUrl.port) {
    try {
      const r = await fetch(`http://${targetUrl.hostname}/`, { redirect: 'manual', headers: { 'user-agent': UA, ...EXTRA_HEADERS }, signal: AbortSignal.timeout(CFG.timeout) });
      await r.body?.cancel();
      const loc = r.headers.get('location') || '';
      if (r.status === 200 || (r.status >= 300 && r.status < 400 && !loc.startsWith('https://')))
        out.push(F(1, 'nohttps', 'Alamat http tidak dialihkan ke https'));
    } catch { /* port 80 tertutup itu wajar */ }
  }
  return out;
}

// DNS, email, dan subdomain: berat dan jarang berubah, jadi dijalankan paling sering sekali per jam.
// ZAP tidak dijalankan dari sini -- hanya memanggil daemon ZAP yang sudah berjalan di mesinmu
// (--zap http://host:port). Spider+passive berjalan tiap siklus seperti pemeriksaan lain; active
// scan (jika --zap-active-scan) hanya dipicu SEKALI per proses, bukan tiap siklus, karena ia
// mengirim payload serangan dan makan waktu lama.
async function zapChecks() {
  if (!ZAP_BASE) return [];
  await zapVersion(ZAP_BASE, ZAP_KEY); // lempar error kalau daemon tidak terjangkau, biar jelas kenapa

  // Spider hanya sekali per proses (bukan tiap siklus) — cegah CPU meledak & multiple spider
  if (!ZAP_SKIP_SPIDER && !zapSpiderDone) {
    send('log', { msg: 'ZAP spider dimulai (hanya sekali per proses)...' });
    await zapSpider(ZAP_BASE, origin, ZAP_KEY);
    zapSpiderDone = true;
    send('log', { msg: 'ZAP spider selesai, mengambil alert...' });
  } else if (ZAP_SKIP_SPIDER && !zapSpiderDone) {
    send('log', { msg: 'ZAP spider dilewati (--zap-skip-spider), memakai data yang sudah ada' });
    zapSpiderDone = true;
  }

  if (ZAP_ACTIVE && !zapChecked) {
    zapChecked = true;
    send('log', { msg: 'ZAP active scan dimulai -- ini mengirim payload serangan sungguhan, bisa makan waktu lama' });
    try {
      await zapActiveScan(ZAP_BASE, origin, ZAP_KEY);
      send('log', { msg: 'ZAP active scan selesai' });
    } catch (e) {
      const msg = `ZAP active scan gagal: ${e.message}`;
      console.error(msg);
      send('log', { msg });
      // Lanjut ambil alert passive yang sudah ada, jangan gagalkan seluruh siklus
    }
  }

  const alerts = await zapAlerts(ZAP_BASE, origin, ZAP_KEY);
  return alertsToFindings(alerts);
}

async function dnsChecks() {
  if (OFFLINE || isLocalHost()) return [];
  if (Date.now() - dnsCache.at > HOUR) {
    const r = await auditDns(targetUrl.hostname, { doh: process.env.DNS_DOH !== '0' }).catch(() => null);
    const certs = r ? await auditSubCerts(r.subdomains).catch(() => []) : [];
    dnsCache = { at: Date.now(), findings: r ? [...r.findings, ...certs] : [], subs: r ? r.subdomains : [] };
  }
  return dnsCache.findings;
}

/* ---------- Siklus pemindaian ---------- */

// Menyimpan hasil satu node, membandingkannya dengan siklus lalu, lalu menyiarkannya.
function finish(n, findings) {
  if (findings.some((f) => f.rule === 'secret')) n.terms = [];
  const uniq = [...new Map(findings.map((f) => [fkey(f), f])).values()];
  const prevKeys = new Set(n.findings.map(fkey));
  const curKeys = new Set(uniq.map(fkey));
  const fresh = uniq.filter((f) => !prevKeys.has(fkey(f)));
  const resolved = n.findings.filter((f) => !curKeys.has(fkey(f)));
  n.findings = uniq;
  n.scanned = true;
  n.seen = cycle;
  send('scan_done', { id: n.id, type: n.type, status: n.status, ms: n.ms, words: n.words, terms: n.terms, findings: uniq, fresh, resolved });
}

async function runCycle() {
  cycle++;
  phase = 'memindai';
  send('cycle_start', { cycle });

  const once = new Set();
  const queue = [];
  let root;
  let rootExtra = [];
  let isIgnored = () => false;

  let safeProbeCount = 0;
  if (MODE === 'web') {
    // Tampilkan root dan node probe DULU (supaya dasbor tidak terlihat beku/0 node), baru jalankan
    // pemeriksaan berat (DNS, TLS, ZAP) yang bisa makan waktu lama. Pemindaian sebenarnya (pump())
    // belum mulai sampai blok ini selesai, tapi setidaknya node sudah terlihat lebih awal.
    root = ensureNode(targetUrl.href, 'page', null);
    queue.push(root);
    root.queued = cycle;
    const ALL_PROBES = [...PROBES, ...loadUserProbes()];
    for (const pr of ALL_PROBES) {
      const n = ensureNode(origin + pr.p, 'file', root.id);
      if (!n) continue;
      n.probe = pr;
      n.queued = cycle;
      addEdge(root.id, n.id);
      queue.push(n);
    }
    send('log', { msg: 'Menjalankan pemeriksaan DNS/TLS/ZAP sebelum mulai merayapi -- bisa makan waktu beberapa puluh detik...' });

    rootExtra = [...(await cycleChecks().catch(() => [])), ...(await dnsChecks().catch(() => []))];
    rootExtra.push(...(await zapChecks().catch((e) => { const msg = `ZAP: ${e.message}`; console.error(msg); send('log', { msg }); return []; })));
    for (const sub of dnsCache.subs) {
      const c = ensureExt(sub, root.id);
      if (c) addEdge(root.id, c.id);
    }
  } else {
    isIgnored = await loadIgnore(rootIsFile ? path.dirname(rootDir) : rootDir);
    if (baseline) baseline.seenFiles = new Set();
    rootExtra = [...lastRemoved];
    if (!rootIsFile && hasGit(rootDir)) {
      const head = await gitHead(rootDir);
      if (head && head !== gitCache.head) {
        gitCache.findings = await scanGitHistory(rootDir).catch(() => []);
        gitCache.head = head;
      }
      rootExtra.push(...gitCache.findings);
    }
    root = ensureFileNode('', rootDir, 'page', null);
    queue.push(root);
    root.queued = cycle;
  }

  async function scanWeb(n) {
    send('scan_start', { id: n.id });
    const found = [];
    const findings = [];
    let resp;
    try {
      resp = await get(n.url, n.probe ? { force: true, maxBytes: 262144 } : {});
    } catch (e) {
      resp = { status: 0, headers: new Headers(), body: '', ms: 0, ct: '', error: e.name === 'AbortError' ? 'timeout' : e.message };
    }
    n.ms = resp.ms;
    n.status = resp.status;
    n.terms = [];
    n.words = 0;

    if (n.probe) {
      const pr = n.probe;
      const hit = resp.status === 200 && pr.ok(resp);
      if (pr.missing) {
        if (resp.status !== 0 && !hit) findings.push(F(pr.missing.lvl, pr.missing.rule, pr.missing.text));
      } else if (hit) {
        findings.push(F(pr.lvl ?? 2, 'exposed', pr.t));
      }
    } else {
      if (resp.status === 0) findings.push(F(1, 'unreachable', `Tidak dapat dijangkau (${resp.error || 'error'})`));
      else if (resp.status >= 500) findings.push(F(1, '5xx', `Server mengembalikan error ${resp.status}`));
      else if (resp.status >= 400) findings.push(F(1, '4xx', `Tautan putus (${resp.status})`));
      if (resp.ms > 3000) findings.push(F(0, 'slow', `Respons lambat (${(resp.ms / 1000).toFixed(1)} dtk)`));

      if (resp.body) {
        if (/html/i.test(resp.ct)) {
          if (ERR_LEAK.test(resp.body)) findings.push(F(1, 'errleak', 'Halaman membocorkan pesan error/stack trace'));
          if (/<title>\s*Index of \/|<h1>\s*Index of \//i.test(resp.body)) findings.push(F(1, 'dirlist', 'Directory listing aktif'));
          if (INVISIBLE_TAG.test(resp.body)) findings.push(F(2, 'inj-hidden', 'Karakter tag Unicode tak terlihat (teknik menyelundupkan prompt)'));
          if (INTERNAL_IP.test(resp.body)) findings.push(F(0, 'internal-ip', 'Alamat IP internal terlihat di sumber halaman'));
        }
        if (/javascript/i.test(resp.ct) && /\/\/[#@]\s*sourceMappingURL=/.test(resp.body))
          findings.push(F(0, 'sourcemap', 'File JavaScript menautkan source map (kode sumber bisa terbaca)'));
      }

      if (resp.status && resp.status < 400) {
        if (/html/i.test(resp.ct)) {
          n.type = 'page';
          findings.push(...analyzeHtml(n, resp, found));
          // Sinyal uji aman (tambahan; tidak mengganti crawler/ZAP/probe yang ada)
          if (shouldProbe(n, { isRoot: n === root, probedCount: safeProbeCount, maxPages: 5 })) {
            safeProbeCount++;
            const sig = await safeSignalsForPage(n.url, async (href) => {
              const r = await get(href, { force: true, maxBytes: 65536 });
              return { status: r.status, body: r.body || '', ct: r.ct };
            });
            findings.push(...sig);
          }
          if (n === root) {
            headerFindings(resp.headers, findings);
            findings.push(...rootExtra);
            const waf = detectWaf(resp.headers);
            if (waf) findings.push(F(0, 'waf', `Terdeteksi WAF/CDN: ${waf} (sebagian pemeriksaan bisa diblokir olehnya, hasil audit bisa tidak lengkap)`));
          }
          cookieFindings(resp.headers, once, findings);
        } else {
          n.type = 'asset';
        }
        findings.push(...findSecrets(resp.body), ...jwtScan(resp.body), ...genericSecretFindings(resp.body));
      }
    }

    for (const { u, kind } of found) {
      if (u.origin === origin) {
        const c = ensureNode(u.href, kind === 'a' ? 'page' : 'asset', n.id);
        if (!c) continue;
        addEdge(n.id, c.id);
        if (c.queued !== cycle) {
          c.queued = cycle;
          queue.push(c);
        }
      } else {
        const c = ensureExt(u.hostname, n.id);
        if (c) addEdge(n.id, c.id);
      }
    }
    finish(n, findings);
  }

  async function scanFs(n) {
    send('scan_start', { id: n.id });
    const t0 = Date.now();
    const findings = [];
    const name = path.basename(n.abs);
    n.terms = [];
    n.words = 0;
    n.sha = null;

    let st;
    try {
      st = await fsp.lstat(n.abs);
    } catch {
      n.status = 0;
      n.ms = 0;
      findings.push(F(1, 'unreachable', 'Tidak dapat dibaca (berkas hilang atau izin ditolak)'));
      return finish(n, findings);
    }
    n.status = 200;
    n.size = st.size;

    if (st.isSymbolicLink()) {
      n.type = 'asset';
      findings.push(F(0, 'file-symlink', 'Symlink (tidak diikuti oleh pemindai)'));
    } else if (st.isDirectory()) {
      n.type = n.rel === '' ? 'page' : 'asset';
      const isVcs = VCS_DIRS.has(name) && n.rel !== '';
      let entries = [];
      if (!isVcs) {
        try {
          entries = (await fsp.readdir(n.abs, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
        } catch {
          findings.push(F(1, 'unreachable', 'Folder tidak dapat dibaca (izin ditolak)'));
        }
      }
      findings.push(...auditDir(name, st, entries.map((e) => e.name), { isRoot: n.rel === '' }));
      for (const e of entries) {
        if (SKIP_DIRS.has(e.name)) continue;
        const rel = n.rel ? `${n.rel}/${e.name}` : e.name;
        const c = ensureFileNode(rel, path.join(n.abs, e.name), e.isDirectory() ? 'asset' : 'page', n.id);
        if (!c) break;
        addEdge(n.id, c.id);
        if (c.queued !== cycle) {
          c.queued = cycle;
          queue.push(c);
        }
      }
    } else if (st.isFile()) {
      const r = await auditFile({ abs: n.abs, rel: n.rel || name, name, st, maxBytes: CFG.maxBytes, isIgnored });
      n.type = r.isText ? 'page' : 'asset';
      n.terms = r.terms;
      n.words = r.words;
      n.sha = r.sha;
      findings.push(...r.findings);
      if (baseline) findings.push(...baseline.fileDrift(n.rel || name, r.sha));
      if (!OFFLINE && DEP_FILES.has(name)) findings.push(...(await auditDepsFile(n.abs, name)));
    } else {
      n.type = 'asset';
      findings.push(F(0, 'file-special', 'Berkas khusus (socket/perangkat) dilewati'));
    }
    if (n === root) findings.push(...rootExtra);
    n.ms = Date.now() - t0;
    finish(n, findings);
  }

  const scanNode = MODE === 'web' ? scanWeb : scanFs;

  let active = 0;
  await new Promise((resolve) => {
    const pump = () => {
      while (active < CFG.concurrency && queue.length) {
        const n = queue.shift();
        active++;
        scanNode(n)
          .catch((e) => send('log', { msg: `Gagal memindai ${n.path}: ${e.message}` }))
          .finally(() => {
            active--;
            setTimeout(pump, CFG.delay);
          });
      }
      if (!active && !queue.length) resolve();
    };
    pump();
  });

  if (MODE === 'web') {
    const attempted = [...nodes.values()].filter((n) => n.type !== 'ext' && n.seen === cycle && n.status);
    const blocked = attempted.filter((n) => n.status === 403 || n.status === 429);
    if (attempted.length >= 5 && blocked.length / attempted.length > 0.3)
      send('log', { msg: `${blocked.length}/${attempted.length} halaman mengembalikan 403/429 — situs mungkin memblokir pemindai (WAF/rate-limit), hasil bisa tidak lengkap` });
  }

  for (const [key, n] of nodes) {
    if (n.seen !== cycle && n !== root) {
      nodes.delete(key);
      byId.delete(n.id);
      send('node_gone', { id: n.id });
    }
  }
  edges = edges.filter(([a, b]) => byId.has(a) && byId.has(b));
  edgeSet = new Set(edges.map(([a, b]) => `${a}-${b}`));

  if (baseline) {
    if (MODE === 'file') lastRemoved = baseline.removed();
    baseline.save();
  }
  try {
    await notifier.cycle(reportItems().map(({ n, f }) => ({ path: n.path, f })), summary());
  } catch { /* notifikasi gagal tidak boleh menghentikan siklus */ }

  phase = 'menunggu';
  nextAt = Date.now() + CFG.interval;
  send('cycle_end', { cycle, nextIn: CFG.interval, summary: summary() });
}

/* ---------- Agent triase (opsional) ---------- */

async function runAgent() {
  if (!agent.enabled || agentBusy) return;
  agentBusy = true;
  try {
    const items = [];
    const byId2 = new Map();
    const files = new Map();
    const sorted = reportItems().filter(({ f }) => f.lvl >= 1);
    for (const { n, f } of sorted) {
      const idx = n.findings.indexOf(f);
      const id = `n${n.id}#${idx}`;
      let snip;
      const line = /\(baris (\d+)\)/.exec(f.text)?.[1];
      if (MODE === 'file' && line && n.abs && f.rule !== 'secret') {
        if (!files.has(n.abs)) files.set(n.abs, await fsp.readFile(n.abs, 'utf8').catch(() => ''));
        snip = snippet(files.get(n.abs), Number(line));
      }
      items.push({ id, path: MODE === 'file' ? n.rel || n.path : n.path, rule: f.rule, text: f.text, lvl: f.lvl, snippet: snip });
      byId2.set(id, { n, f });
    }
    const verdicts = await agent.triage(items);
    const out = [];
    for (const [id, v] of verdicts) {
      const { n, f } = byId2.get(id);
      (n.triage ||= {})[fkey(f)] = v;
      out.push({ id: n.id, key: fkey(f), ...v });
    }
    if (out.length) send('triage', { items: out });
    const live = items
      .map((it) => ({ ...it, ...(verdicts.get(it.id) || { verdict: 'perlu_tinjauan', prioritas: 3 }) }))
      .filter((it) => it.verdict !== 'positif_palsu')
      .sort((a, b) => a.prioritas - b.prioritas);
    agentPlan = await agent.plan(live);
    send('plan', { plan: agentPlan });
  } catch (e) {
    send('log', { msg: `Agent gagal: ${e.message}` });
  } finally {
    agentBusy = false;
  }
}

async function loop() {
  for (;;) {
    try {
      await runCycle();
      runAgent();
    } catch (e) {
      console.error('Siklus gagal:', e);
      send('log', { msg: `Siklus gagal: ${e.message}` });
      phase = 'menunggu';
      nextAt = Date.now() + CFG.interval;
    }
    await sleep(CFG.interval);
  }
}

/* ---------- Server HTTP ---------- */

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };
const FILES = { '/': 'index.html', '/app.js': 'app.js', '/style.css': 'style.css' };
const CSP =
  "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'";

const server = http.createServer((req, res) => {
  const loopback = ['127.0.0.1', 'localhost', '::1'].includes(CFG.bind);
  if (loopback && !/^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(req.headers.host || '')) {
    res.writeHead(403);
    return res.end('Host tidak diizinkan');
  }
  const url = new URL(req.url, 'http://x');

  if (url.pathname === '/events') {
    res.writeHead(200, {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    res.write('retry: 3000\n\n');
    res.write(`event: snapshot\ndata: ${JSON.stringify(snapshot())}\n\n`);
    clients.add(res);
    req.on('close', () => clients.delete(res));
    return;
  }

  if (url.pathname === '/report.json') {
    res.writeHead(200, {
      'content-type': 'application/json; charset=utf-8',
      'content-disposition': 'attachment; filename="laporan-pemindaian.json"',
    });
    return res.end(JSON.stringify(report(), null, 2));
  }

    if (url.pathname === '/report-pimpinan.md' || url.pathname === '/pimpinan.md') {
    res.writeHead(200, {
      'content-type': 'text/markdown; charset=utf-8',
      'content-disposition': 'attachment; filename="laporan-pimpinan.md"',
    });
    return res.end(reportMd());
  }
  if (url.pathname === '/report.md') {
    res.writeHead(200, {
      'content-type': 'text/markdown; charset=utf-8',
      'content-disposition': 'attachment; filename="laporan-pemindaian.md"',
    });
    return res.end(reportMd());
  }

  const file = FILES[url.pathname];
  if (file) {
    fs.readFile(path.join(DIR, 'public', file), (err, buf) => {
      if (err) {
        res.writeHead(500);
        return res.end('Gagal membaca berkas');
      }
      res.writeHead(200, {
        'content-type': MIME[path.extname(file)],
        'content-security-policy': CSP,
        'x-content-type-options': 'nosniff',
        'cache-control': 'no-store',
      });
      res.end(buf);
    });
    return;
  }

  res.writeHead(404);
  res.end('Tidak ditemukan');
});

/* ---------- Mode CI: satu siklus, tulis laporan, keluar dengan kode ---------- */

async function runOnce() {
  await runCycle();
  const rootNode = nodes.get('fs:');
  if (rootNode && lastRemoved.length) rootNode.findings.push(...lastRemoved); // berkas hilang tampil di laporan mode CI
  await runAgent();
  const s = summary();
  const items = reportItems().map(({ n, f }) => ({ path: MODE === 'file' ? n.rel || n.path : n.url, f }));
  const write = (file, data) => fs.writeFileSync(file, data);
  if (flags['--sarif']) write(flags['--sarif'], JSON.stringify(toSarif(items, { mode: MODE, target: MODE === 'web' ? origin : label }), null, 1));
  if (flags['--json']) write(flags['--json'], JSON.stringify(report(), null, 2));
  if (flags['--md']) write(flags['--md'], reportMd());

  console.log(`Target : ${MODE === 'web' ? origin : rootDir}`);
  console.log(`Skor   : ${s.skor}/100 (${s.nilai}) · ${s.kritis} kritis, ${s.sedang} sedang, ${s.info} info · ${s.halaman} node`);
  for (const { n, f } of reportItems().filter(({ f }) => f.lvl >= 1).slice(0, 15))
    console.log(`  [${LEVEL[f.lvl].toUpperCase()}] ${MODE === 'file' ? n.rel || n.path : n.path}: ${f.text}`);

  const failOn = String(flags['--fail-on'] || 'kritis').toLowerCase();
  const threshold = { kritis: 2, sedang: 1, info: 0, tidak: 99 }[failOn] ?? 2;
  const bad = items.filter(({ f }) => f.lvl >= threshold).length;
  if (bad) console.log(`Gagal: ${bad} temuan di atau di atas tingkat "${failOn}".`);
  process.exit(bad ? 1 : 0);
}

/* ---------- Umpan log SSH dan honeypot ---------- */

function startIntel() {
  const warn = new Set();
  const onError = (file) => (e) => {
    if (warn.has(file)) return;
    warn.add(file);
    console.error(`Tidak bisa membaca ${file}: ${e.code || e.message}. Cek path dan izin bacanya.`);
  };
  if (flags['--ssh-log']) tailFile(flags['--ssh-log'], (l, o) => intel.ingest(parseSshLine(l), o), { onError: onError(flags['--ssh-log']) });
  if (flags['--honeypot-log']) tailFile(flags['--honeypot-log'], (l, o) => intel.ingest(parseCowrie(l), o), { onError: onError(flags['--honeypot-log']) });
  let last = '';
  setInterval(() => {
    if (!clients.size) return;
    const cur = JSON.stringify([intel.top(), intel.total]);
    if (cur === last) return;
    last = cur;
    send('intel_top', { top: intel.top(), total: intel.total });
  }, 4000).unref();
}

if (ONCE) {
  runOnce().catch((e) => {
    console.error('Audit gagal:', e.message);
    process.exit(2);
  });
} else {
  setInterval(() => {
    for (const c of clients) c.write(': ping\n\n');
  }, 20000);

  server.listen(CFG.port, CFG.bind, () => {
    console.log(`Mode       : ${MODE === 'web' ? 'audit situs web' : 'audit berkas lokal'}`);
    console.log(`Target     : ${MODE === 'web' ? origin : rootDir}`);
    console.log(`Dasbor     : http://${CFG.bind === '0.0.0.0' ? 'localhost' : CFG.bind}:${CFG.port}`);
    console.log(`Pindai ulang tiap ${CFG.interval / 1000} dtk, ${CFG.concurrency} kaki aktif, maksimal ${CFG.maxPages} node`);
    if (OFFLINE) console.log('Mode offline: pemeriksaan CVE, DNS, dan subdomain dilewati.');
    if (Object.keys(EXTRA_HEADERS).length) console.log(`Auth       : memakai ${Object.keys(EXTRA_HEADERS).join(', ')} pada setiap permintaan -- pemindai bertindak sebagai sesi/akun ini.`);
    if (agent.enabled) console.log(`Agent      : aktif (${agent.model}). Potongan kode yang disamarkan dikirim ke API Claude.`);
    else if (flags['--agent']) console.log('Agent      : --agent diberikan tetapi ANTHROPIC_API_KEY belum diatur, jadi dimatikan.');
    if (notifier.enabled) console.log('Notifikasi : aktif');
    if (PROFIL) console.log(`Profil     : ${PROFIL}`);
    if (ZAP_BASE) console.log(`ZAP        : ${ZAP_BASE}${ZAP_ACTIVE ? ' (ACTIVE SCAN -- mengirim payload serangan)' : ' (spider + passive saja)'}${ZAP_SKIP_SPIDER ? ' [skip-spider]' : ''}`);
    if (baseline) console.log(`Baseline   : ${baseline.fresh ? 'belum ada, siklus pertama akan merekam' : 'ditemukan, perubahan akan diperiksa'}`);
    if (intelOn) startIntel();
    loop();
  });
}
