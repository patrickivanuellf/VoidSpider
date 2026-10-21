/* Audit DNS dan email untuk domain milikmu: SPF, DMARC, DKIM, CAA, DNSSEC, serta subdomain
   yang menunjuk ke layanan yang sudah tidak ada (risiko subdomain takeover).
   Daftar subdomain diambil dari Certificate Transparency (crt.sh), yaitu data publik. */

import dns from 'node:dns/promises';
import net from 'node:net';
import { F } from './rules.js';

const SLD = new Set(['co.id', 'or.id', 'ac.id', 'go.id', 'web.id', 'my.id', 'sch.id', 'net.id', 'biz.id', 'co.uk', 'org.uk', 'com.au', 'co.jp', 'com.br', 'co.nz', 'com.sg']);
const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'mail', 'dkim', 's1', 's2', 'smtp', 'zoho', 'mandrill'];

// Fingerprint halaman "layanan tidak ada" per penyedia
const PROVIDERS = [
  { cname: /github\.io$/i, body: /There isn't a GitHub Pages site here/i, name: 'GitHub Pages' },
  { cname: /herokuapp\.com$|herokudns\.com$/i, body: /No such app/i, name: 'Heroku' },
  { cname: /s3[.-][\w.-]*amazonaws\.com$|s3-website/i, body: /NoSuchBucket/i, name: 'AWS S3' },
  { cname: /azurewebsites\.net$|cloudapp\.net$|trafficmanager\.net$|blob\.core\.windows\.net$/i, body: /404 Web Site not found|Microsoft Azure Web App - Error 404|NoSuchBucket|BlobNotFound/i, name: 'Azure' },
  { cname: /netlify\.app$|netlify\.com$/i, body: /Not Found - Request ID/i, name: 'Netlify' },
  { cname: /surge\.sh$/i, body: /project not found/i, name: 'Surge' },
  { cname: /ghost\.io$/i, body: /The thing you were looking for is no longer here|Failed to resolve DNS path/i, name: 'Ghost' },
  { cname: /fastly\.net$/i, body: /Fastly error: unknown domain/i, name: 'Fastly' },
  { cname: /pantheonsite\.io$/i, body: /404 error unknown site/i, name: 'Pantheon' },
  { cname: /myshopify\.com$/i, body: /Sorry, this shop is currently unavailable/i, name: 'Shopify' },
  { cname: /wordpress\.com$/i, body: /Do you want to register/i, name: 'WordPress.com' },
];

const COMMON_SUBS = [
  'www', 'api', 'staging', 'dev', 'test', 'admin', 'mail', 'webmail', 'ftp', 'vpn', 'git', 'gitlab',
  'jenkins', 'ci', 'grafana', 'kibana', 'portal', 'panel', 'cpanel', 'ns1', 'ns2', 'smtp', 'autodiscover',
  'cdn', 'static', 'assets', 'old', 'backup', 'beta', 'demo', 'internal', 'app', 'shop', 'blog', 'm', 'mobile',
];

/** Hanya resolusi DNS lewat resolver publik, tidak pernah menghubungi server web target langsung. */
export async function bruteSubdomains(domain, r = dns) {
  const found = new Set();
  for (let i = 0; i < COMMON_SUBS.length; i += 8) {
    const batch = COMMON_SUBS.slice(i, i + 8);
    await Promise.all(batch.map(async (s) => {
      const host = `${s}.${domain}`;
      for (const fn of [() => r.resolve4(host), () => r.resolve6(host), () => r.resolveCname(host)]) {
        try { await fn(); found.add(host); return; } catch { /* coba cara lain */ }
      }
    }));
  }
  return [...found];
}

export function baseDomain(host) {
  const h = host.toLowerCase().replace(/\.$/, '');
  if (net.isIP(h) || !h.includes('.') || h === 'localhost') return null;
  const parts = h.split('.');
  const last2 = parts.slice(-2).join('.');
  return SLD.has(last2) && parts.length >= 3 ? parts.slice(-3).join('.') : last2;
}

async function txt(r, name) {
  try { return (await r.resolveTxt(name)).map((a) => a.join('')); } catch { return null; }
}

export function spfFindings(records, hasMx) {
  const out = [];
  const spf = (records || []).filter((t) => /^v=spf1\b/i.test(t));
  const lvl = hasMx ? 1 : 0;
  if (!spf.length) return [F(lvl, 'spf', hasMx ? 'SPF tidak ada (siapa pun bisa memalsukan email dari domain ini)' : 'SPF tidak ada (disarankan v=spf1 -all untuk domain yang tidak mengirim email)')];
  if (spf.length > 1) return [F(1, 'spf', 'Ada lebih dari satu record SPF (tidak valid, email bisa ditolak)')];
  const s = spf[0];
  if (/\s\+all\b|\s\?all\b/.test(s)) out.push(F(1, 'spf', 'SPF mengizinkan semua pengirim (+all atau ?all)'));
  else if (/\s~all\b/.test(s)) out.push(F(0, 'spf', 'SPF memakai ~all (softfail), pertimbangkan -all'));
  else if (!/\s-all\b/.test(s) && !/redirect=/.test(s)) out.push(F(0, 'spf', 'SPF tidak ditutup dengan -all atau ~all'));
  const lookups = (s.match(/\b(?:include:|a\b|mx\b|ptr\b|exists:|redirect=)/g) || []).length;
  if (lookups > 10) out.push(F(0, 'spf', `SPF melebihi batas 10 DNS lookup (perkiraan ${lookups})`));
  return out;
}

export function dmarcFindings(records, hasMx) {
  const d = (records || []).find((t) => /^v=DMARC1\b/i.test(t));
  if (!d) return [F(hasMx ? 1 : 0, 'dmarc', 'DMARC tidak ada')];
  const out = [];
  const p = /\bp=(\w+)/i.exec(d)?.[1]?.toLowerCase();
  if (p === 'none') out.push(F(0, 'dmarc', 'DMARC p=none (hanya memantau, belum menolak email palsu)'));
  if (!/\brua=/i.test(d)) out.push(F(0, 'dmarc', 'DMARC tanpa alamat laporan (rua)'));
  const pct = /\bpct=(\d+)/i.exec(d)?.[1];
  if (pct && Number(pct) < 100) out.push(F(0, 'dmarc', `DMARC hanya berlaku untuk ${pct}% email`));
  return out;
}

async function dnssec(domain, fetchImpl) {
  try {
    const res = await fetchImpl(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=DS`, {
      headers: { accept: 'application/dns-json' },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return null;
    const j = await res.json();
    return Array.isArray(j.Answer) && j.Answer.some((a) => a.type === 43);
  } catch { return null; }
}

export async function ctSubdomains(domain, fetchImpl = fetch) {
  try {
    const res = await fetchImpl(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { signal: AbortSignal.timeout(25000) });
    if (!res.ok) return [];
    const rows = await res.json();
    const set = new Set();
    for (const r of rows) {
      for (const n of String(r.name_value || '').split('\n')) {
        const h = n.trim().toLowerCase().replace(/^\*\./, '');
        if (h === domain || h.endsWith(`.${domain}`)) set.add(h);
      }
    }
    return [...set].filter((h) => h !== domain).sort().slice(0, 80);
  } catch { return []; }
}

async function dangling(r, sub, fetchImpl) {
  let cname;
  try { cname = (await r.resolveCname(sub))[0]; } catch { return null; }
  if (!cname) return null;
  const miss = async (fn) => { try { await fn(cname); return false; } catch (e) { return e.code === 'ENOTFOUND'; } };
  if ((await miss((c) => r.resolve4(c))) && (await miss((c) => r.resolve6(c))))
    return F(2, 'takeover', `${sub} → CNAME ${cname} yang sudah tidak ada (dangling)`);
  const prov = PROVIDERS.find((p) => p.cname.test(cname));
  if (prov) {
    for (const scheme of ['https', 'http']) {
      try {
        const res = await fetchImpl(`${scheme}://${sub}/`, { redirect: 'manual', signal: AbortSignal.timeout(8000), headers: { 'user-agent': 'LabaLabaPemindai/2.0' } });
        const body = (await res.text()).slice(0, 20000);
        if (prov.body.test(body)) return F(2, 'takeover', `${sub} → ${prov.name} (${cname}) menampilkan halaman "belum diklaim", rawan diambil alih`);
        break;
      } catch { /* coba skema lain */ }
    }
  }
  return null;
}

export async function auditDns(host, { r = dns, fetchImpl = fetch, ct = true, doh = true, brute = true } = {}) {
  const domain = baseDomain(host);
  if (!domain) return { findings: [], subdomains: [], domain: null };
  const out = [];

  let mx = [];
  try { mx = await r.resolveMx(domain); } catch { /* tanpa MX */ }
  const hasMx = mx.length > 0;

  const root = await txt(r, domain);
  if (root !== null || hasMx) out.push(...spfFindings(root, hasMx));
  out.push(...dmarcFindings(await txt(r, `_dmarc.${domain}`), hasMx));

  if (hasMx) {
    let found = false;
    for (const sel of DKIM_SELECTORS) {
      const t = await txt(r, `${sel}._domainkey.${domain}`);
      if (t && t.some((x) => /v=DKIM1|p=/i.test(x))) { found = true; break; }
    }
    if (!found) out.push(F(0, 'dkim', 'DKIM tidak ditemukan pada selector umum (belum tentu tidak ada, selector bisa memakai nama lain)'));
  }

  let caa = [];
  try { caa = await r.resolveCaa(domain); } catch { /* tanpa CAA */ }
  if (!caa.length) out.push(F(0, 'caa', 'Record CAA tidak ada'));

  if (doh) {
    const ds = await dnssec(domain, fetchImpl);
    if (ds === false) out.push(F(0, 'dnssec', 'DNSSEC tidak aktif'));
  }

  const bruted = brute ? await bruteSubdomains(domain, r).catch(() => []) : [];
  const ctSubs = ct ? await ctSubdomains(domain, fetchImpl) : [];
  const subdomains = [...new Set([...ctSubs, ...bruted])].sort().slice(0, 100);
  for (let i = 0; i < subdomains.length; i += 6) {
    const res = await Promise.all(subdomains.slice(i, i + 6).map((s) => dangling(r, s, fetchImpl)));
    out.push(...res.filter(Boolean));
  }
  return { findings: out, subdomains, domain };
}
