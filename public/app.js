const $ = (s) => document.querySelector(s);
const cv = $('#c');
const ctx = cv.getContext('2d');
const tip = $('#tip');
const LV = ['info', 'sedang', 'kritis'];
const TAU = Math.PI * 2;
const MONO = '"IBM Plex Mono", ui-monospace, Menlo, monospace';
const PAL = { gray: [150, 156, 162], cyan: [76, 195, 238], blue: [44, 138, 200], pink: [240, 87, 122] };
const LABEL = {
  csp: 'csp', xfo: 'frame', xcto: 'nosniff', refpol: 'referrer', hsts: 'hsts', xpb: 'x-powered', serverver: 'server',
  cors: 'cors', 'cookie-secure': 'cookie', 'cookie-httponly': 'cookie', 'cookie-samesite': 'cookie', mixed: 'mixed',
  sri: 'sri', formhttp: 'form-http', csrf: 'csrf', pwhttp: 'pw-http', 'inj-hidden': 'injection', 'inj-visible': 'prompt?',
  secret: 'secret', exposed: 'exposed', '4xx': '404', '5xx': '5xx', slow: 'lambat', unreachable: 'down', tls: 'tls', nohttps: 'http',
  'jwt-none': 'jwt-none', 'jwt-noexp': 'jwt-noexp', 'jwt-longexp': 'jwt-exp', 'jwt-claim': 'jwt-claim',
  'secret-generic': 'secret?', waf: 'waf', blocked: 'blocked',
  'csp-weak': 'csp', 'hsts-weak': 'hsts', permpol: 'permissions', generator: 'versi', 'cookie-none': 'cookie', pwget: 'pw-get',
  'pw-cache': 'cache', dirlist: 'listing', errleak: 'error-leak', sourcemap: 'sourcemap', 'internal-ip': 'ip-internal', securitytxt: 'security.txt',
  'file-sensitive': 'sensitif', 'file-git': 'vcs', 'file-exec': 'biner', 'file-doubleext': 'ext-ganda', 'file-masquerade': 'samaran', 'file-perm': 'izin',
  'code-eval': 'eval', 'code-exec': 'exec', 'code-xss': 'xss', 'code-sqli': 'sqli', 'code-tls': 'tls-off', 'code-hash': 'hash', 'code-deser': 'deser',
  'code-lfi': 'lfi', 'code-shell': 'curl|sh', 'code-perm': '777', 'code-debug': 'debug', 'trojan-source': 'bidi', zerowidth: 'zero-width',
  'pkg-script': 'npm-script', 'pkg-pin': 'versi-lepas', 'pkg-nolock': 'lockfile', 'docker-root': 'root', 'docker-latest': 'latest',
};

let W = 800, H = 600, dpr = 1;
// Area bebas = layar dikurangi bilah atas dan panel telemetri. Kamera berpusat di area ini.
let CX = 400, CY = 320, CXt = 400, CYt = 320, FW = 800, FH = 560, sized = false, dragMoved = false;
const nodes = new Map();
let list = [];
let links = [];
const edgeSet = new Set();
const view = { x: 0, y: 0, z: 0.85, px: 0, py: 0, uz: 1, mode: 'follow' };
let cycleNo = 0, phase = 'menunggu', deadline = 0, scanned = 0;
let T = 0, last = 0, frameNo = 0, alpha = 1, flash = 0;
let hoverId = null, drag = null, pan = null;
const ALPHA_T = 0.012;
const focus = { idx: 0, name: 'menunggu', sub: '' };

const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
const wrap = (a) => { while (a > Math.PI) a -= TAU; while (a < -Math.PI) a += TAU; return a; };
const lerp = (a, b, k) => a + (b - a) * k;
const rgba = (c, a) => `rgba(${Math.round(c[0])},${Math.round(c[1])},${Math.round(c[2])},${a})`;
function srng(seed) {
  let a = seed | 0;
  return () => {
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function hash(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}

function size() {
  dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth || cv.parentElement?.clientWidth || 800;
  const h = cv.clientHeight || cv.parentElement?.clientHeight || 600;
  if (w < 10 || h < 10) return;
  W = w;
  H = h;
  const nw = Math.round(W * dpr);
  const nh = Math.round(H * dpr);
  if (cv.width !== nw || cv.height !== nh) {
    cv.width = nw;
    cv.height = nh;
  }
  const hidden = document.body.classList.contains('hide');
  const narrow = window.innerWidth <= 860;
  let right = 0, bottom = 0;
  if (!hidden) { if (narrow) bottom = Math.round(H * 0.46) + 8; else right = 380 + 24; }
  const x1 = W - right, y0 = 48, y1 = H - bottom;
  FW = Math.max(200, x1);
  FH = Math.max(200, y1 - y0);
  CXt = x1 / 2;
  CYt = (y0 + y1) / 2;
  if (!sized) { CX = CXt; CY = CYt; sized = true; }
}
new ResizeObserver(size).observe(cv);
window.addEventListener('resize', size);

/* ---------- Data node dan gugus kata ---------- */

function shortName(p, type) {
  if (type === 'ext') return p;
  if (p === '/' || p === '') return 'beranda';
  const seg = p.split('?')[0].split('/').filter(Boolean).pop() || p;
  return seg.replace(/\.[a-z0-9]+$/i, '').slice(0, 20);
}

function buildCluster(n) {
  const rnd = srng(n.id * 9301 + 7);
  n.dots = [];
  n.dust = [];
  if (n.type !== 'page') {
    n.nw = 0;
    n.rad = n.type === 'ext' ? 4 : 3.4;
    return;
  }
  const nw = n.terms.length ? Math.min(44, n.terms.length) : 16;
  n.nw = nw;
  n.rad = 28 + Math.sqrt(nw) * 4.5;
  const cs = [];
  const nc = 2 + Math.floor(rnd() * 2);
  for (let i = 0; i < nc; i++) {
    const a = rnd() * TAU, d = rnd() * n.rad * 0.38;
    cs.push([Math.cos(a) * d, Math.sin(a) * d]);
  }
  const rot = rnd() * TAU, ex = 0.8 + rnd() * 0.5;
  const place = (spread) => {
    const c = cs[Math.floor(rnd() * cs.length)];
    const a = rnd() * TAU, r = Math.sqrt(rnd()) * n.rad * spread;
    const x = Math.cos(a) * r * ex, y = Math.sin(a) * r / ex;
    return [c[0] + x * Math.cos(rot) - y * Math.sin(rot), c[1] + x * Math.sin(rot) + y * Math.cos(rot)];
  };
  for (let i = 0; i < nw; i++) { const p = place(0.55); n.dots.push({ x: p[0], y: p[1], s: 1.2 + rnd() * 0.8 }); }
  for (let i = 0; i < 70; i++) { const p = place(1.0); n.dust.push({ x: p[0], y: p[1], a: 0.15 + rnd() * 0.35 }); }
  n.rd = Math.min(n.rd || 0, nw);
}

function addEdge(a, b) {
  if (a == null || b == null || a === b) return;
  // normalize so a-b and b-a are the same
  const lo = a < b ? a : b, hi = a < b ? b : a;
  const k = `${lo}-${hi}`;
  if (edgeSet.has(k)) return;
  edgeSet.add(k);
  links.push([a, b]);
}

function addNode(p) {
  const old = nodes.get(p.id);
  if (old) { old.type = p.type; return; }
  const par = p.from != null ? nodes.get(p.from) : null;
  // Orbital / galactic placement around parent
  const a = Math.random() * TAU;
  const dist = par ? (50 + Math.random() * 70 + (p.type === 'page' ? 30 : 0)) : (Math.random() * 80);
  const n = {
    id: p.id, path: p.path, type: p.type, from: p.from, name: shortName(p.path, p.type),
    findings: p.findings || [], triage: p.triage || {}, scanned: !!p.scanned, scanning: false,
    words: p.words || 0, ms: p.ms || 0, status: p.status || 0, terms: p.terms || [],
    x: (par && Number.isFinite(par.x) ? par.x : 0) + Math.cos(a) * dist,
    y: (par && Number.isFinite(par.y) ? par.y : 0) + Math.sin(a) * dist,
    vx: 0, vy: 0, fx: null, fy: null,
    rad: 5, dots: [], dust: [], nw: 0, rd: 0, col: PAL.gray.slice(), ga: 0.06,
  };
  buildCluster(n);
  if (n.scanned) n.rd = n.nw;
  nodes.set(n.id, n);
  list = [...nodes.values()];
  if (p.from != null) addEdge(p.from, p.id);
  alpha = Math.max(alpha, 0.3);
}

function removeNode(id) {
  nodes.delete(id);
  list = [...nodes.values()];
  links = links.filter(([a, b]) => a !== id && b !== id);
  edgeSet.clear();
  links.forEach(([a, b]) => edgeSet.add(`${a}-${b}`));
  cables.forEach((c) => { if (c.id === id) c.rel = true; });
  for (let i = tags.length - 1; i >= 0; i--) if (tags[i].id === id) tags.splice(i, 1);
  alpha = Math.max(alpha, 0.2);
}

const maxLvl = (n) => n.findings.reduce((m, f) => Math.max(m, f.lvl), -1);
const stateOf = (n) => (n.scanning ? 1 : !n.scanned ? 0 : maxLvl(n) >= 1 ? 3 : 2);
const dotPos = (n, i) => { const d = n.dots[i]; return d ? [n.x + d.x, n.y + d.y] : [n.x, n.y]; };

/* ---------- Simulasi gaya (galaxy / brain lobes) ---------- */

const REP = 9, GRAV = 0.0035, LINK_STRENGTH = 0.32;

function tick() {
  alpha += (ALPHA_T - alpha) * 0.018;
  // Hierarchical spring: parent-child form tight modules (brain lobes / galaxy arms)
  const maxLinks = Math.min(links.length, 600);
  for (let li = 0; li < maxLinks; li++) {
    const [a, b] = links[li];
    const s = nodes.get(a), t = nodes.get(b);
    if (!s || !t || !Number.isFinite(s.x) || !Number.isFinite(t.x)) continue;
    const x = t.x - s.x, y = t.y - s.y;
    const d = Math.hypot(x, y) || 1e-6;
    const sr = Math.max(2, s.rad || 4), tr = Math.max(2, t.rad || 4);
    // Tighter rest length for page-page (modules), looser for assets/ext
    const bothPage = s.type === 'page' && t.type === 'page';
    const rest = sr + tr + (bothPage ? 130 : 70);
    const strength = bothPage ? LINK_STRENGTH : LINK_STRENGTH * 0.55;
    const f = ((d - rest) / d) * alpha * strength;
    if (!Number.isFinite(f)) continue;
    s.vx += x * f * 0.5; s.vy += y * f * 0.5;
    t.vx -= x * f * 0.5; t.vy -= y * f * 0.5;
  }
  // Soft repulsion — only nearby, creates organic spacing inside lobes
  const L = list;
  const nCap = Math.min(L.length, 180);
  for (let i = 0; i < nCap; i++) {
    const p = L[i];
    if (!Number.isFinite(p.x)) continue;
    for (let j = i + 1; j < nCap; j++) {
      const q = L[j];
      if (!Number.isFinite(q.x)) continue;
      let dx = q.x - p.x, dy = q.y - p.y, d2 = dx * dx + dy * dy;
      if (d2 > 640000) continue;
      if (d2 < 4) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 4; }
      const d = Math.sqrt(d2);
      const ux = dx / d, uy = dy / d;
      const pr = Math.max(2, p.rad || 4), qr = Math.max(2, q.rad || 4);
      let F = (REP * alpha * Math.sqrt(pr * qr)) / (d + 8);
      const minD = pr + qr + 34;
      if (d < minD) F += (minD - d) * 0.28;
      if (!Number.isFinite(F)) continue;
      p.vx -= ux * F; p.vy -= uy * F;
      q.vx += ux * F; q.vy += uy * F;
    }
  }
  // Weak central gravity + gentle orbital bias → galaxy feel
  for (const n of L) {
    if (!Number.isFinite(n.x) || !Number.isFinite(n.y) || !Number.isFinite(n.vx) || !Number.isFinite(n.vy)) {
      n.x = (Math.random() - 0.5) * 120;
      n.y = (Math.random() - 0.5) * 120;
      n.vx = 0; n.vy = 0;
      continue;
    }
    n.vx -= n.x * GRAV * alpha;
    n.vy -= n.y * GRAV * alpha;
    // Tiny tangential drift so arms slowly curve
    n.vx += -n.y * 0.0009 * alpha;
    n.vy += n.x * 0.0009 * alpha;
    if (n.fx != null) { n.x = n.fx; n.y = n.fy; n.vx = 0; n.vy = 0; continue; }
    n.vx *= 0.72; n.vy *= 0.72;
    const sv = Math.hypot(n.vx, n.vy);
    if (sv > 55) { n.vx *= 55 / sv; n.vy *= 55 / sv; }
    n.x += n.vx; n.y += n.vy;
  }
}

let acc = 0;
function simulate(dt) {
  acc = Math.min(acc + dt, 0.1);
  while (acc >= 1 / 60) { tick(); acc -= 1 / 60; }
}

/* ---------- Makhluk: badan, serabut, tentakel manik-manik ---------- */

const NC = 8;
const sp = { x: 0, y: 0, vx: 0, vy: 0, h: -Math.PI / 2, c: 0, s: -1 };
const cables = Array.from({ length: NC }, (_, i) => ({ i, ph: 'idle', t: 0, hold: 0, id: null, rel: false, tents: [] }));
const pending = [];
const tags = [];
const fan = (() => {
  const r = srng(42), out = [];
  for (let k = 0; k < 38; k++) {
    const u = k / 37;
    out.push({ a: (u - 0.5) * 2 * 1.75, len: 26 + r() * 20 + Math.sin(u * Math.PI) * 14, ph: r() * TAU, bend: (r() - 0.5) * 0.5 });
  }
  return out;
})();

function setRot() {
  const phi = sp.h + Math.PI / 2;
  sp.c = Math.cos(phi); sp.s = Math.sin(phi);
}
const wpt = (lx, ly) => [sp.x + lx * sp.c - ly * sp.s, sp.y + lx * sp.s + ly * sp.c];
const mouth = () => wpt(0, -22);

function initSpider() {
  const root = list.find((n) => n.from == null && Number.isFinite(n.x));
  sp.x = root && Number.isFinite(root.x) ? root.x : 0;
  sp.y = root && Number.isFinite(root.y) ? root.y + 90 : 60;
  sp.vx = 0; sp.vy = 0; sp.h = -Math.PI / 2;
  setRot();
  cables.forEach((c) => { c.ph = 'idle'; c.id = null; c.t = 0; c.rel = false; c.tents = []; });
  pending.length = 0;
  tags.length = 0;
}

function addTag(n, di, kind) {
  const text = n.terms[di];
  if (!text) return;
  const ex = tags.find((t) => t.id === n.id && t.di === di);
  if (ex) { ex.born = T; return; }
  const mine = tags.filter((t) => t.id === n.id);
  if (mine.length >= 3) tags.splice(tags.indexOf(mine[0]), 1);
  if (tags.length > 22) tags.shift();
  tags.push({ id: n.id, di, text, kind, born: T, ttl: 1.7 });
}

function assignCable(id) {
  const c = cables.find((q) => q.ph === 'idle');
  if (c) startCable(c, id);
  else pending.push(id);
}

function startCable(c, id) {
  const n = nodes.get(id);
  if (!n) return;
  const m = mouth();
  c.ph = 'ext'; c.t = 0; c.id = id; c.rel = false; c.hold = 0;
  const cnt = n.type === 'page' ? 4 : 1;
  c.tents = [];
  for (let i = 0; i < cnt; i++) c.tents.push({ di: -1, tx: m[0], ty: m[1], cx: m[0], cy: m[1], cvx: 0, cvy: 0, ph: Math.random() * TAU, nt: 0 });
  if (n.type === 'page') n.rd = 0;
  focus.idx++;
  focus.name = n.name;
  focus.sub = n.path;
}

function updCables(dt) {
  const m = mouth();
  for (const c of cables) {
    if (c.ph === 'idle') {
      while (pending.length) {
        const id = pending.shift();
        const n = nodes.get(id);
        if (n && n.scanning) { startCable(c, id); break; }
      }
      continue;
    }
    const n = c.id != null ? nodes.get(c.id) : null;
    if (!n) c.rel = true;
    if (c.ph === 'ext') {
      c.t += dt * 2.6;
      if (c.t >= 1) { c.t = 1; c.ph = 'hold'; c.hold = 0.55; }
    } else if (c.ph === 'hold') {
      c.hold -= dt;
      if ((c.rel && c.hold <= 0) || c.hold < -25) c.ph = 'ret';
    } else if (c.ph === 'ret') {
      c.t -= dt * 2.4;
      if (c.t <= 0) { c.t = 0; c.ph = 'idle'; c.id = null; c.rel = false; c.tents = []; continue; }
    }
    if (n && n.type === 'page' && c.ph !== 'ret') {
      const cap = c.rel ? n.nw : n.nw * 0.9;
      n.rd = Math.min(cap, n.rd + dt * n.nw * 1.1);
    }
    c.tents.forEach((tt, k) => {
      let gx = m[0], gy = m[1];
      if (n && c.ph !== 'ret') {
        if (n.type === 'page' && n.nw) {
          tt.nt -= dt;
          if (tt.nt <= 0 || tt.di < 0) {
            tt.nt = 0.16 + Math.random() * 0.2;
            tt.di = clamp(Math.floor(n.rd - Math.random() * 9), 0, n.nw - 1);
            if (c.ph === 'hold' && k % 2 === 0) addTag(n, tt.di, 'cyan');
          }
          const p = dotPos(n, tt.di); gx = p[0]; gy = p[1];
        } else { gx = n.x; gy = n.y; }
      }
      if (c.ph === 'ext') {
        const e = 1 - Math.pow(1 - c.t, 3);
        tt.tx = m[0] + (gx - m[0]) * e; tt.ty = m[1] + (gy - m[1]) * e;
      } else {
        const kk = Math.min(1, dt * (c.ph === 'ret' ? 9 : 11));
        tt.tx += (gx - tt.tx) * kk; tt.ty += (gy - tt.ty) * kk;
      }
      const len = Math.hypot(tt.tx - m[0], tt.ty - m[1]) || 1;
      const sag = Math.sin(T * 2.6 + tt.ph) * 0.17 * len * (c.ph === 'hold' ? 0.7 : 1);
      const cx = (m[0] + tt.tx) / 2 - ((tt.ty - m[1]) / len) * sag;
      const cy = (m[1] + tt.ty) / 2 + ((tt.tx - m[0]) / len) * sag;
      tt.cvx += ((cx - tt.cx) * 70 - tt.cvx * 7) * dt;
      tt.cvy += ((cy - tt.cy) * 70 - tt.cvy * 7) * dt;
      tt.cx += tt.cvx * dt; tt.cy += tt.cvy * dt;
    });
  }
  for (let i = tags.length - 1; i >= 0; i--) if (T - tags[i].born > tags[i].ttl) tags.splice(i, 1);
}

function updBody(dt) {
  // Recover spider from NaN
  if (!Number.isFinite(sp.x) || !Number.isFinite(sp.y) || !Number.isFinite(sp.vx) || !Number.isFinite(sp.vy)) {
    sp.x = 0; sp.y = 60; sp.vx = 0; sp.vy = 0; sp.h = -Math.PI / 2;
    setRot();
  }
  const act = cables.filter((c) => (c.ph === 'ext' || c.ph === 'hold') && nodes.has(c.id));
  let tx = sp.x, ty = sp.y, ax = 0, ay = 0, have = false;
  if (act.length) {
    have = true;
    let valid = 0;
    for (const c of act) {
      const n = nodes.get(c.id);
      if (n && Number.isFinite(n.x) && Number.isFinite(n.y)) { ax += n.x; ay += n.y; valid++; }
    }
    if (valid) { ax /= valid; ay /= valid; } else { have = false; }
    if (have && act.length === 1) {
      const n = nodes.get(act[0].id);
      if (n) {
        const dx = ax - sp.x, dy = ay - sp.y, d = Math.hypot(dx, dy) || 1, stop = (n.rad || 30) + 50;
        if (d > stop) { tx = ax - (dx / d) * stop; ty = ay - (dy / d) * stop; }
      }
    } else if (have) { tx = ax; ty = ay; }
  } else if (list.length) {
    // Idle: slowly return toward the center of mass of page nodes (or root)
    let sx = 0, sy = 0, cnt = 0;
    for (const n of list) {
      if (n.type === 'page' && Number.isFinite(n.x) && Number.isFinite(n.y)) { sx += n.x; sy += n.y; cnt++; }
    }
    if (cnt > 0) {
      ax = sx / cnt; ay = sy / cnt;
      tx = ax; ty = ay + 40;
      have = true;
    } else {
      const root = list.find((n) => n.from == null && Number.isFinite(n.x));
      if (root) { tx = root.x; ty = root.y + 60; have = true; }
    }
  }
  const pull = have && act.length ? 5.5 : 1.8;
  sp.vx += ((tx - sp.x) * pull - sp.vx * 3.1) * dt;
  sp.vy += ((ty - sp.y) * pull - sp.vy * 3.1) * dt;
  const sv = Math.hypot(sp.vx, sp.vy);
  if (sv > 420) { sp.vx *= 420 / sv; sp.vy *= 420 / sv; }
  sp.x += sp.vx * dt; sp.y += sp.vy * dt;
  let want = sp.h;
  if (sv > 30) want = Math.atan2(sp.vy, sp.vx);
  else if (have) want = Math.atan2(ay - sp.y, ax - sp.x);
  if (Number.isFinite(want)) sp.h += wrap(want - sp.h) * Math.min(1, dt * 5);
  setRot();
}

/* ---------- Kamera ---------- */

function updCamera(dt) {
  if (!list.length) return;
  // Recover view from NaN
  if (!Number.isFinite(view.x) || !Number.isFinite(view.y) || !Number.isFinite(view.z)) {
    view.x = Number.isFinite(sp.x) ? sp.x : 0;
    view.y = Number.isFinite(sp.y) ? sp.y : 0;
    view.z = 0.85;
    view.px = 0; view.py = 0; view.uz = 1;
  }
  let tx = Number.isFinite(sp.x) ? sp.x : 0;
  let ty = Number.isFinite(sp.y) ? sp.y : 0;
  let tz = 0.85;
  if (view.mode === 'all') {
    let x0 = Infinity, x1 = -Infinity, y0 = Infinity, y1 = -Infinity;
    let count = 0;
    for (const n of list) {
      if (n.type === 'ext' || !Number.isFinite(n.x) || !Number.isFinite(n.y)) continue;
      const r = n.rad || 10;
      x0 = Math.min(x0, n.x - r);
      x1 = Math.max(x1, n.x + r);
      y0 = Math.min(y0, n.y - r);
      y1 = Math.max(y1, n.y + r);
      count++;
    }
    if (count > 0 && Number.isFinite(x0) && Number.isFinite(x1)) {
      const pad = 180;
      tx = (x0 + x1) / 2;
      ty = (y0 + y1) / 2;
      const dx = Math.max(x1 - x0 + pad, 200);
      const dy = Math.max(y1 - y0 + pad, 200);
      tz = clamp(Math.min(FW / dx, FH / dy), 0.1, 1.4);
    }
  } else {
    const act = cables.filter((c) => c.ph === 'ext' || c.ph === 'hold');
    let spread = 220;
    for (const c of act) {
      const n = nodes.get(c.id);
      if (n && Number.isFinite(n.x)) spread = Math.max(spread, Math.hypot(n.x - sp.x, n.y - sp.y) + (n.rad || 30) + 50);
    }
    if (act.length === 0 && list.length) {
      let nearest = 0;
      for (const n of list) {
        if (n.type !== 'page' || !Number.isFinite(n.x)) continue;
        const d = Math.hypot(n.x - sp.x, n.y - sp.y) + (n.rad || 30);
        if (d < 400) nearest = Math.max(nearest, d);
      }
      if (nearest > 0) spread = Math.max(spread, nearest + 80);
    }
    tz = clamp((Math.min(W, H) * 0.46) / spread, 0.28, 1.25);
    tx = sp.x + (Number.isFinite(sp.vx) ? sp.vx * 0.25 : 0);
    ty = sp.y + (Number.isFinite(sp.vy) ? sp.vy * 0.25 : 0);
  }
  if (!Number.isFinite(tx)) tx = 0;
  if (!Number.isFinite(ty)) ty = 0;
  if (!Number.isFinite(tz)) tz = 0.85;
  const k = Math.min(1, dt * 2.4);
  view.x += (tx + view.px - view.x) * k;
  view.y += (ty + view.py - view.y) * k;
  view.z += (tz * view.uz - view.z) * k;
}

/* ---------- Gambar ---------- */

function colorTarget(n) {
  const st = stateOf(n);
  if (st === 0) return [PAL.gray, 0.18];
  if (st === 1) return [PAL.cyan, 0.35];
  if (st === 2) return [PAL.blue, 0.28];
  return [PAL.pink, maxLvl(n) === 2 ? 0.45 : 0.34];
}

function drawTag(x, y, text, kind, a, iz) {
  ctx.font = `500 ${9 * iz}px ${MONO}`;
  const w = ctx.measureText(text).width + 9 * iz, h = 13 * iz;
  const bx = x + 8 * iz, by = y - h - 5 * iz;
  ctx.globalAlpha = a;
  ctx.lineWidth = 0.8 * iz;
  ctx.strokeStyle = kind === 'pink' ? rgba(PAL.pink, 0.9) : rgba(PAL.cyan, 0.8);
  ctx.beginPath();
  ctx.moveTo(x, y); ctx.lineTo(bx, by + h);
  ctx.stroke();
  if (kind === 'pink') {
    ctx.fillStyle = rgba(PAL.pink, 0.88);
    ctx.fillRect(bx, by, w, h);
    ctx.fillStyle = '#1b0b12';
  } else {
    ctx.fillStyle = 'rgba(10,14,16,0.75)';
    ctx.fillRect(bx, by, w, h);
    ctx.strokeRect(bx, by, w, h);
    ctx.fillStyle = '#cfefff';
  }
  ctx.textBaseline = 'middle';
  ctx.fillText(text, bx + 4.5 * iz, by + h / 2 + 0.5 * iz);
  ctx.globalAlpha = 1;
}

function drawBeads(tt, m, iz) {
  // Pure geometric tentacle: single elegant cubic-ish curve + sparse mathematical nodes
  const len = Math.hypot(tt.tx - m[0], tt.ty - m[1]);
  if (len < 4) return;
  const cnt = Math.min(28, Math.max(4, Math.floor(len / 14)));
  // Guide curve
  ctx.strokeStyle = 'rgba(120,190,230,0.22)';
  ctx.lineWidth = 0.9 * iz;
  ctx.lineCap = 'round';
  ctx.beginPath();
  ctx.moveTo(m[0], m[1]);
  ctx.quadraticCurveTo(tt.cx, tt.cy, tt.tx, tt.ty);
  ctx.stroke();
  // Discrete geometric beads (equal parameter spacing on the quadratic)
  for (let i = 1; i <= cnt; i++) {
    const u = i / (cnt + 0.5);
    const a = (1 - u) * (1 - u), b = 2 * (1 - u) * u, c = u * u;
    const x = a * m[0] + b * tt.cx + c * tt.tx;
    const y = a * m[1] + b * tt.cy + c * tt.ty;
    const r = (0.7 + u * 1.1) * iz;
    // outer ring
    ctx.strokeStyle = `rgba(160,220,255,${0.25 + u * 0.35})`;
    ctx.lineWidth = 0.7 * iz;
    ctx.beginPath();
    ctx.arc(x, y, r * 1.8, 0, TAU);
    ctx.stroke();
    // core point
    ctx.fillStyle = `rgba(220,245,255,${0.55 + u * 0.4})`;
    ctx.beginPath();
    ctx.arc(x, y, r * 0.55, 0, TAU);
    ctx.fill();
  }
}

function drawCreature(iz0) {
  // Mathematical organism: nested ellipses + logarithmic radial spines
  const S = 1.4, iz = iz0 / S;
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';
  ctx.save();
  ctx.translate(sp.x, sp.y);
  ctx.rotate(sp.h + Math.PI / 2);
  ctx.scale(S, S);
  const mv = Math.min(1, Math.hypot(sp.vx || 0, sp.vy || 0) / 180);
  const pulse = 1 + Math.sin(T * 1.8) * 0.025;

  // Radial logarithmic spines (clean, geometric, not cartoon fluff)
  const spines = 16;
  for (let i = 0; i < spines; i++) {
    const a0 = (i / spines) * TAU - Math.PI / 2;
    const len = 22 + 10 * Math.sin(i * 1.7 + T * 0.4) + mv * 4;
    const bend = Math.sin(T * 1.3 + i * 0.9) * 0.22;
    const a1 = a0 + bend;
    const bx = Math.sin(a0) * 9;
    const by = -Math.cos(a0) * 7;
    const ex = Math.sin(a1) * (9 + len);
    const ey = -Math.cos(a1) * (7 + len * 0.85);
    const mx = (bx + ex) * 0.5 + Math.cos(a0) * (3 + mv * 2);
    const my = (by + ey) * 0.5 + Math.sin(a0) * (2 + mv);
    ctx.strokeStyle = `rgba(130,200,235,${0.18 + 0.12 * Math.abs(Math.cos(a0))})`;
    ctx.lineWidth = 0.65 * iz;
    ctx.beginPath();
    ctx.moveTo(bx, by);
    ctx.quadraticCurveTo(mx, my, ex, ey);
    ctx.stroke();
    // terminal geometric node
    ctx.fillStyle = `rgba(190,230,255,${0.5 + 0.3 * Math.abs(Math.cos(a0))})`;
    ctx.beginPath();
    ctx.arc(ex, ey, 0.9 * iz, 0, TAU);
    ctx.fill();
  }

  // Nested ellipses — pure form
  ctx.strokeStyle = 'rgba(76,195,238,0.18)';
  ctx.lineWidth = 0.7 * iz;
  ctx.beginPath();
  ctx.ellipse(0, 0, 26 * pulse, 20 * pulse, 0, 0, TAU);
  ctx.stroke();

  ctx.strokeStyle = 'rgba(76,195,238,0.35)';
  ctx.lineWidth = 0.9 * iz;
  ctx.beginPath();
  ctx.ellipse(0, 0, 18 * pulse, 13.5 * pulse, 0, 0, TAU);
  ctx.stroke();

  ctx.fillStyle = 'rgba(8,10,12,0.92)';
  ctx.beginPath();
  ctx.ellipse(0, 0, 14.5 * pulse, 11 * pulse, 0, 0, TAU);
  ctx.fill();
  ctx.strokeStyle = 'rgba(76,195,238,0.85)';
  ctx.lineWidth = 1.3 * iz;
  ctx.stroke();

  // Inner core — mathematical focus point
  ctx.strokeStyle = 'rgba(76,195,238,0.45)';
  ctx.lineWidth = 0.7 * iz;
  ctx.beginPath();
  ctx.ellipse(0, 0, 7.5, 5.5, 0, 0, TAU);
  ctx.stroke();

  const g = ctx.createRadialGradient(0, 0, 0, 0, 0, 6.5);
  g.addColorStop(0, 'rgba(255,100,140,0.9)');
  g.addColorStop(0.6, 'rgba(255,80,120,0.35)');
  g.addColorStop(1, 'rgba(255,80,120,0)');
  ctx.fillStyle = g;
  ctx.beginPath();
  ctx.arc(0, 0, 6.5, 0, TAU);
  ctx.fill();

  ctx.fillStyle = 'rgba(255,140,170,0.95)';
  ctx.beginPath();
  ctx.arc(0, 0, 1.6, 0, TAU);
  ctx.fill();

  ctx.restore();
}

function draw() {
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.fillStyle = '#0b0f13';
  ctx.fillRect(0, 0, W, H);
  ctx.save();
  ctx.translate(CX, CY);
  ctx.scale(view.z, view.z);
  ctx.translate(-view.x, -view.y);
  const z = view.z, iz = 1 / z;
  const vx0 = view.x - CX / z - 120, vx1 = view.x + (W - CX) / z + 120;
  const vy0 = view.y - CY / z - 120, vy1 = view.y + (H - CY) / z + 120;
  const vis = (n) => n.x > vx0 - n.rad && n.x < vx1 + n.rad && n.y > vy0 - n.rad && n.y < vy1 + n.rad;

  ctx.lineWidth = 0.85 * iz;
  ctx.strokeStyle = 'rgba(140,180,210,0.14)';
  ctx.beginPath();
  for (const [a, b] of links) {
    const na = nodes.get(a), nb = nodes.get(b);
    if (!na || !nb) continue;
    ctx.moveTo(na.x, na.y); ctx.lineTo(nb.x, nb.y);
  }
  ctx.stroke();

  for (const n of list) {
    const [tc, ta] = colorTarget(n);
    for (let i = 0; i < 3; i++) n.col[i] += (tc[i] - n.col[i]) * 0.06;
    n.ga += (ta - n.ga) * 0.06;
    if (!vis(n)) continue;
    const st = stateOf(n);
    if (n.type !== 'page') {
      const col = st === 1 ? PAL.cyan : st === 3 ? PAL.pink : n.type === 'ext' ? PAL.gray : st === 2 ? [190, 225, 245] : PAL.gray;
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.rad * (z < 0.6 ? 1.4 : 1), 0, TAU);
      if (n.type === 'ext') { ctx.strokeStyle = rgba(col, 0.6); ctx.lineWidth = 1 * iz; ctx.stroke(); }
      else { ctx.fillStyle = rgba(col, st === 0 ? 0.4 : st === 2 ? 0.6 : 0.9); ctx.fill(); }
      if (st === 3) { ctx.strokeStyle = rgba(PAL.pink, 0.5); ctx.lineWidth = 0.9 * iz; ctx.beginPath(); ctx.arc(n.x, n.y, n.rad + 4 * iz + Math.sin(T * 3) * iz, 0, TAU); ctx.stroke(); }
      continue;
    }
    const R = n.rad * 1.7;
    for (let k = 0; k < 2; k++) {
      const ox = n.x + (k ? n.rad * 0.35 : -n.rad * 0.25), oy = n.y + (k ? -n.rad * 0.2 : n.rad * 0.15);
      const g = ctx.createRadialGradient(ox, oy, 0, ox, oy, R * (k ? 0.8 : 1));
      g.addColorStop(0, rgba(n.col, n.ga * (k ? 0.8 : 1)));
      g.addColorStop(1, rgba(n.col, 0));
      ctx.fillStyle = g;
      ctx.beginPath();
      ctx.arc(ox, oy, R, 0, TAU);
      ctx.fill();
    }
    const tint = st === 3 ? PAL.pink : st === 0 ? PAL.gray : PAL.cyan;
    ctx.fillStyle = rgba(tint, 0.5);
    for (const d of n.dust) ctx.fillRect(n.x + d.x, n.y + d.y, iz * 0.9, iz * 0.9);
    const flagged = st === 3;
    for (let i = 0; i < n.dots.length; i++) {
      const d = n.dots[i];
      const lit = i < n.rd;
      ctx.fillStyle = lit ? (flagged && i % 3 === 0 ? 'rgba(255,128,160,0.95)' : 'rgba(205,240,255,0.95)') : 'rgba(146,152,158,0.75)';
      ctx.beginPath();
      ctx.arc(n.x + d.x, n.y + d.y, d.s * (z < 0.5 ? 1.5 : 1), 0, TAU);
      ctx.fill();
    }
  }

  ctx.textBaseline = 'alphabetic';
  for (const n of list) {
    if (n.type !== 'page' || !vis(n) || z < 0.22) continue;
    const lx = n.x - n.rad * 0.95, ly = n.y - n.rad * 1.1;
    const st = stateOf(n);
    ctx.font = `600 ${12 * iz}px ${MONO}`;
    ctx.fillStyle = st === 3 ? 'rgba(255,150,176,0.95)' : 'rgba(150,215,245,0.95)';
    ctx.fillText(n.name, lx, ly);
    const total = n.words || (n.nw ? '...' : 0);
    const done = n.scanned ? n.words : n.nw ? Math.round((n.rd / n.nw) * (n.words || 0)) : 0;
    const state = n.scanning ? 'reading' : !n.scanned ? 'queued' : st === 3 ? 'flagged' : 'done';
    ctx.font = `400 ${9 * iz}px ${MONO}`;
    ctx.fillStyle = 'rgba(150,158,166,0.85)';
    ctx.fillText(`${done}/${total} words · ${state}`, lx, ly + 11 * iz);
  }

  for (const n of list) {
    if (n.type !== 'page' || !n.nw || !vis(n) || stateOf(n) !== 3 || z < 0.4) continue;
    n.findings.filter((f) => f.lvl >= 1).slice(0, 4).forEach((f) => {
      const di = hash(f.rule + n.id) % n.nw;
      const p = dotPos(n, di);
      drawTag(p[0], p[1], LABEL[f.rule] || f.rule, 'pink', 0.95, iz);
    });
  }
  for (const t of tags) {
    const n = nodes.get(t.id);
    if (!n || !vis(n)) continue;
    const age = (T - t.born) / t.ttl;
    const p = dotPos(n, t.di);
    drawTag(p[0], p[1], t.text, t.kind, clamp(1.6 - age * 1.4, 0, 1), iz);
  }

  const m = mouth();
  for (const c of cables) {
    if (c.ph === 'idle') continue;
    c.tents.forEach((tt) => drawBeads(tt, m, iz));
  }
  drawCreature(iz);
  ctx.restore();

  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.save();
  ctx.translate(0, 52);
  const jit = Math.sin(T * 37) > 0.97 ? (Math.random() - 0.5) * 5 : 0;
  const title = `${String(focus.idx).padStart(2, '0')} ${focus.name.toUpperCase()}`;
  ctx.fillStyle = 'rgba(76,195,238,0.9)';
  ctx.fillRect(14, 16, 3, 40);
  ctx.textBaseline = 'alphabetic';
  ctx.font = `600 20px ${MONO}`;
  ctx.fillStyle = 'rgba(76,195,238,0.7)'; ctx.fillText(title, 25 - 1.6 + jit, 36);
  ctx.fillStyle = 'rgba(240,87,122,0.7)'; ctx.fillText(title, 25 + 1.6 + jit, 36);
  ctx.fillStyle = '#e8eef3'; ctx.fillText(title, 25 + jit, 36);
  ctx.font = `400 10px ${MONO}`;
  ctx.fillStyle = 'rgba(140,150,158,0.9)';
  ctx.fillText(focus.sub.slice(0, 48), 25, 52);

  // subtle status
  ctx.font = `400 10px ${MONO}`;
  ctx.fillStyle = 'rgba(140,160,180,0.55)';
  const pages = list.filter(n => n.type === 'page').length;
  ctx.fillText(`${list.length} node · ${pages} halaman · ${links.length} tautan`, 25, 68);

  ctx.restore();

  if (flash > 0.02) {
    ctx.strokeStyle = `rgba(255,70,50,${flash * 0.85})`;
    ctx.lineWidth = 4;
    ctx.strokeRect(2, 2, W - 4, H - 4);
    flash *= 0.94;
  }
}

function frame(ts) {
  const dt = Math.min(0.05, (ts - last) / 1000 || 0);
  last = ts;
  T += dt;
  frameNo++;
  CX += (CXt - CX) * Math.min(1, dt * 8);
  CY += (CYt - CY) * Math.min(1, dt * 8);
  simulate(dt);
  updBody(dt);
  updCables(dt);
  updCamera(dt);
  draw();
  requestAnimationFrame(frame);
}

/* ---------- Log, laporan, status ---------- */

function addLog(text, cls) {
  const box = $('#log');
  const stick = box.scrollTop + box.clientHeight >= box.scrollHeight - 10;
  const el = document.createElement('div');
  el.className = `ln ${cls || ''}`;
  el.textContent = text;
  box.appendChild(el);
  while (box.children.length > 300) box.removeChild(box.firstChild);
  if (stick) box.scrollTop = box.scrollHeight;
}

const clock = () => new Date().toTimeString().slice(0, 8);

function logScan(n, d) {
  const t = clock();
  addLog(`${t}  ${d.status || 'ERR'}  ${n.path}  ${d.ms} ms`, 'dim');
  d.fresh.forEach((f) => addLog(`${t}  ${LV[f.lvl]}  ${n.path}  ${f.text}`, `l${f.lvl}`));
  d.resolved.forEach((f) => addLog(`${t}  teratasi  ${n.path}  ${f.text}`, 'ok'));
}

let reportQueued = false;
function renderReport() {
  if (reportQueued) return;
  reportQueued = true;
  requestAnimationFrame(() => {
    reportQueued = false;
    const c = [0, 0, 0];
    const items = [];
    nodes.forEach((n) => n.findings.forEach((f) => {
      c[f.lvl]++;
      if (f.lvl >= 1) items.push({ n, f });
    }));
    const pri = ({ n, f }) => {
      const t = n.triage && n.triage[`${f.rule}|${f.text}`];
      return t ? (t.verdict === 'positif_palsu' ? 9 : t.prioritas) : 5;
    };
    items.sort((a, b) => b.f.lvl - a.f.lvl || pri(a) - pri(b) || a.n.path.localeCompare(b.n.path));
    $('#c2').textContent = c[2];
    $('#c1').textContent = c[1];
    $('#c0').textContent = c[0];
    const ul = $('#open');
    ul.textContent = '';
    if (!items.length) {
      const li = document.createElement('li');
      li.className = 'empty';
      li.textContent = 'Belum ada temuan sedang atau kritis.';
      ul.appendChild(li);
      return;
    }
    items.slice(0, 40).forEach(({ n, f }) => {
      const li = document.createElement('li');
      const b = document.createElement('span');
      b.className = `badge l${f.lvl}`;
      b.textContent = LV[f.lvl];
      const code = document.createElement('code');
      code.textContent = n.path;
      const txt = document.createElement('span');
      txt.textContent = f.text;
      li.append(b, code, txt);
      const tv = n.triage && n.triage[`${f.rule}|${f.text}`];
      if (tv) {
        const v = document.createElement('small');
        v.className = `verdict ${tv.verdict}`;
        v.textContent = `agent: ${tv.verdict.replace('_', ' ')}${tv.alasan ? ` · ${tv.alasan}` : ''}`;
        li.appendChild(v);
        if (tv.verdict === 'positif_palsu') li.classList.add('fp');
      }
      if (f.fix) {
        const fx = document.createElement('small');
        fx.className = 'fix';
        fx.textContent = `Saran: ${f.fix}`;
        li.appendChild(fx);
      }
      ul.appendChild(li);
    });
  });
}

function renderPlan(plan) {
  const box = $('#planBox');
  const ol = $('#plan');
  ol.textContent = '';
  box.hidden = !plan.length;
  plan.forEach((p) => {
    const li = document.createElement('li');
    li.textContent = p.tindakan;
    if (p.alasan) {
      const s = document.createElement('small');
      s.textContent = p.alasan;
      li.appendChild(s);
    }
    ol.appendChild(li);
  });
}

function renderIntel(top, total) {
  $('#intelBox').hidden = false;
  $('#intelTotal').textContent = `${total.fail} percobaan gagal · ${total.ok} login berhasil`;
  const ul = $('#intelList');
  ul.textContent = '';
  top.forEach((r) => {
    const li = document.createElement('li');
    const ip = document.createElement('code');
    ip.textContent = r.ip;
    const c = document.createElement('span');
    c.textContent = `${r.fails}x gagal · ${r.users} user${r.oks ? ` · ${r.oks} berhasil` : ''}`;
    if (r.oks && r.fails >= 3) li.className = 'hot';
    li.append(ip, c);
    ul.appendChild(li);
  });
}

function setScore(sum) {
  if (!sum || sum.skor == null) return;
  const g = $('#grade');
  g.textContent = sum.nilai;
  g.className = `g g${sum.nilai}`;
  $('#score').textContent = `skor ${sum.skor}/100`;
}

function updatePhase() {
  const total = list.filter((n) => n.type !== 'ext').length;
  if (phase === 'memindai') {
    $('#phase').textContent = `siklus ${cycleNo}: memindai ${scanned} dari ${total} halaman`;
  } else if (cycleNo) {
    const s = Math.max(0, Math.round((deadline - Date.now()) / 1000));
    $('#phase').textContent = `siklus ${cycleNo} selesai, pindai ulang dalam ${s} dtk`;
  } else {
    $('#phase').textContent = 'menunggu siklus pertama';
  }
}
setInterval(updatePhase, 1000);

function setConn(ok) {
  const el = $('#conn');
  el.className = `pill ${ok ? 'ok' : 'bad'}`;
  el.textContent = ok ? 'tersambung' : 'terputus, mencoba lagi';
}

/* ---------- Koneksi SSE ---------- */

const es = new EventSource('/events');
es.onopen = () => setConn(true);
es.onerror = () => setConn(false);
const on = (name, fn) => es.addEventListener(name, (e) => fn(JSON.parse(e.data)));

on('snapshot', (s) => {
  nodes.clear();
  list = [];
  links = [];
  edgeSet.clear();
  const host = s.label || new URL(s.target).host;
  $('#target').textContent = host;
  setScore(s.summary);
  renderPlan(s.plan || []);
  if (s.intel) renderIntel(s.intel.top, s.intel.total);
  cycleNo = s.cycle;
  phase = s.phase;
  deadline = Date.now() + s.nextIn;
  s.nodes.forEach(addNode);
  // Only take a reasonable number of edges to avoid explosion
  const edgeList = Array.isArray(s.edges) ? s.edges.slice(0, 2000) : [];
  edgeList.forEach(([a, b]) => addEdge(a, b));
  scanned = s.nodes.filter((p) => p.scanned && p.type !== 'ext').length;
  // Sanitize any bad positions right after load
  for (const n of list) {
    if (!Number.isFinite(n.x) || !Number.isFinite(n.y)) {
      n.x = (Math.random() - 0.5) * 100;
      n.y = (Math.random() - 0.5) * 100;
      n.vx = 0; n.vy = 0;
    }
  }
  alpha = 1;
  for (let i = 0; i < 400; i++) tick();
  alpha = 0.35;
  initSpider();
  view.mode = 'follow';
  view.px = 0; view.py = 0; view.uz = 1;
  view.x = Number.isFinite(sp.x) ? sp.x : 0;
  view.y = Number.isFinite(sp.y) ? sp.y : 0;
  view.z = 0.85;
  $('#fit').textContent = 'Lihat semua';
  focus.idx = 0; focus.name = 'siap'; focus.sub = host;
  addLog(`${clock()}  tersambung ke ${host} · ${list.length} node`, 'sys');
  // Isi siaran dengan riwayat temuan supaya panel tidak kosong saat dibuka di tengah siklus.
  const past = [];
  for (const n of list) for (const f of n.findings || []) if (f.lvl >= 1) past.push({ n, f });
  past.sort((a, b) => b.f.lvl - a.f.lvl);
  if (past.length) addLog(`${clock()}  riwayat ${Math.min(past.length, 25)} temuan teratas`, 'dim');
  for (const { n, f } of past.slice(0, 25)) addLog(`${clock()}  ${LV[f.lvl].toUpperCase()}  ${n.path}: ${f.text}`, `l${f.lvl}`);
  renderReport();
  updatePhase();
});

on('node', (p) => { addNode(p); updatePhase(); });
on('edge', ([a, b]) => addEdge(a, b));
on('node_gone', ({ id }) => { removeNode(id); renderReport(); });

on('scan_start', ({ id }) => {
  const n = nodes.get(id);
  if (!n) return;
  n.scanning = true;
  assignCable(id);
});

on('scan_done', (d) => {
  const n = nodes.get(d.id);
  if (!n) return;
  n.scanning = false;
  n.scanned = true;
  n.type = d.type;
  n.ms = d.ms;
  n.status = d.status;
  n.words = d.words;
  n.terms = d.terms || [];
  n.findings = d.findings;
  const hadRad = n.rad;
  buildCluster(n);
  n.rd = n.nw;
  if (n.rad !== hadRad) alpha = Math.max(alpha, 0.3);
  scanned++;
  if (d.fresh.some((f) => f.lvl === 2)) flash = 1;
  const cb = cables.find((c) => c.id === d.id);
  if (cb) cb.rel = true;
  logScan(n, d);
  renderReport();
  updatePhase();
});

on('cycle_start', (d) => {
  cycleNo = d.cycle;
  phase = 'memindai';
  scanned = 0;
  focus.idx = 0;
  addLog(`${clock()}  siklus ${d.cycle} dimulai`, 'sys');
  updatePhase();
});

on('cycle_end', (d) => {
  phase = 'menunggu';
  deadline = Date.now() + d.nextIn;
  const s = d.summary;
  setScore(s);
  addLog(`${clock()}  siklus ${d.cycle} selesai: ${s.kritis} kritis, ${s.sedang} sedang, ${s.info} info · skor ${s.skor} (${s.nilai})`, 'sys');
  updatePhase();
});

on('log', (d) => addLog(`${clock()}  ${d.msg}`, 'l1'));

on('triage', (d) => {
  for (const t of d.items) {
    const n = nodes.get(t.id);
    if (n) (n.triage ||= {})[t.key] = { verdict: t.verdict, alasan: t.alasan, prioritas: t.prioritas };
  }
  addLog(`${clock()}  agent menilai ${d.items.length} temuan`, 'sys');
  renderReport();
});
on('plan', (d) => renderPlan(d.plan || []));

on('intel', (e) => {
  if (e.top) renderIntel(e.top, e.total);
  const who = e.kind === 'honeypot' ? 'honeypot' : 'ssh';
  if (e.type === 'brute') addLog(`${clock()}  SERANGAN ${who} ${e.ip}: ${e.count} gagal login dalam semenit (user: ${(e.users || []).join(', ')})`, 'l2');
  else if (e.type === 'success-after-fails') addLog(`${clock()}  PERHATIAN login ssh berhasil "${e.user}" dari ${e.ip} setelah ${e.fails} kegagalan`, 'l2');
  else if (e.type === 'command') addLog(`${clock()}  honeypot ${e.ip}: ${e.cmd}`, 'l1');
  else if (e.type === 'ok') addLog(`${clock()}  ${who} login berhasil ${e.user || ''} dari ${e.ip}`, 'l1');
});
on('intel_top', (d) => renderIntel(d.top, d.total));

/* ---------- Interaksi ---------- */

const toWorld = (mx, my) => [(mx - CX) / view.z + view.x, (my - CY) / view.z + view.y];

function hit(mx, my) {
  const [wx, wy] = toWorld(mx, my);
  let best = null, bd = Infinity;
  for (const n of list) {
    const d = Math.hypot(n.x - wx, n.y - wy);
    const lim = n.type === 'page' ? n.rad * 0.8 : n.rad + 6 / view.z;
    if (d < lim && d < bd) { bd = d; best = n; }
  }
  return best;
}

function showTip(n, mx, my) {
  const state = n.type === 'ext' ? 'domain pihak ketiga' : !n.scanned ? 'belum dipindai' : n.findings.length ? '' : 'tidak ada temuan';
  const lines = [n.path, `${n.type}${n.ms ? `, ${n.ms} ms` : ''}${n.words ? `, ${n.words} kata` : ''}`];
  if (state) lines.push(state);
  n.findings.forEach((f) => lines.push(`${LV[f.lvl]}: ${f.text}`));
  n.findings.filter((f) => f.lvl >= 1 && f.fix).slice(0, 2).forEach((f) => lines.push(`saran: ${f.fix}`));
  tip.textContent = lines.join('\n');
  tip.hidden = false;
  tip.style.left = `${Math.max(4, Math.min(mx + 14, W - 330))}px`;
  tip.style.top = `${Math.max(4, Math.min(my + 14, H - 40))}px`;
}

cv.addEventListener('pointerdown', (e) => {
  const r = cv.getBoundingClientRect();
  const h = hit(e.clientX - r.left, e.clientY - r.top);
  cv.setPointerCapture(e.pointerId);
  if (h) { drag = h; dragMoved = false; h.fx = h.x; h.fy = h.y; alpha = Math.max(alpha, 0.3); tip.hidden = true; }
  else pan = { x: e.clientX, y: e.clientY };
});

cv.addEventListener('pointermove', (e) => {
  const r = cv.getBoundingClientRect();
  const mx = e.clientX - r.left, my = e.clientY - r.top;
  if (drag) {
    const [wx, wy] = toWorld(mx, my);
    drag.fx = wx; drag.fy = wy;
    dragMoved = true;
    alpha = Math.max(alpha, 0.25);
    return;
  }
  if (pan) {
    view.px -= (e.clientX - pan.x) / view.z;
    view.py -= (e.clientY - pan.y) / view.z;
    pan.x = e.clientX; pan.y = e.clientY;
    return;
  }
  const h = hit(mx, my);
  hoverId = h ? h.id : null;
  cv.style.cursor = h ? 'pointer' : 'default';
  if (h) showTip(h, mx, my); else tip.hidden = true;
});

function release() {
  if (drag) { if (!dragMoved) { drag.fx = null; drag.fy = null; } drag = null; }
  pan = null;
}
cv.addEventListener('pointerup', release);
cv.addEventListener('pointercancel', release);
cv.addEventListener('pointerleave', () => { hoverId = null; tip.hidden = true; });
cv.addEventListener('wheel', (e) => {
  e.preventDefault();
  view.uz = clamp(view.uz * Math.exp(-e.deltaY * 0.0015), 0.15, 4);
}, { passive: false });

function recenter() { view.px = 0; view.py = 0; view.uz = 1; }
cv.addEventListener('dblclick', (e) => {
  const r = cv.getBoundingClientRect();
  const h = hit(e.clientX - r.left, e.clientY - r.top);
  if (h) { h.fx = null; h.fy = null; alpha = Math.max(alpha, 0.3); } else recenter();
});
$('#fit').addEventListener('click', () => {
  recenter();
  view.mode = view.mode === 'follow' ? 'all' : 'follow';
  $('#fit').textContent = view.mode === 'follow' ? 'Lihat semua' : 'Ikuti laba-laba';
});

function setPanel(open) {
  document.body.classList.toggle('hide', !open);
  $('#reopen').hidden = open;
  size();
}
$('#collapse').addEventListener('click', () => setPanel(false));
$('#reopen').addEventListener('click', () => setPanel(true));
window.addEventListener('keydown', (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey || e.key.toLowerCase() !== 'h') return;
  setPanel(document.body.classList.contains('hide'));
});
const bootAt = Date.now();
const p2 = (v) => String(v).padStart(2, '0');
function tickClock() {
  const s = Math.floor((Date.now() - bootAt) / 1000);
  $('#mclock').textContent = `${p2(Math.floor(s / 3600))}:${p2(Math.floor(s / 60) % 60)}:${p2(s % 60)}`;
  $('#utc').textContent = new Date().toISOString().slice(11, 19);
}
setInterval(tickClock, 1000);
tickClock();

size();
renderReport();
updatePhase();
setRot();
requestAnimationFrame(frame);
