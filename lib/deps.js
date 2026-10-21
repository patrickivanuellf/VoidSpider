/* Pemeriksaan kerentanan dependensi lewat OSV.dev.
   Yang dikirim ke OSV hanya nama paket, ekosistem, dan versi. Isi berkasmu tidak ikut terkirim. */

import fs from 'node:fs/promises';
import { F } from './rules.js';

export const DEP_FILES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'requirements.txt', 'composer.lock']);

const BASE = process.env.OSV_URL || 'https://api.osv.dev';
const TTL = 6 * 3600 * 1000;
const cache = new Map(); // "eko|nama|versi" -> { at, ids }
const details = new Map(); // id -> detail ringkas

/* ---------- Parser ---------- */

export function parseDeps(name, text) {
  const out = new Map();
  const add = (ecosystem, pkg, version) => {
    if (!pkg || !version || !/^\d/.test(String(version))) return;
    out.set(`${ecosystem}|${pkg}|${version}`, { ecosystem, name: pkg, version: String(version) });
  };

  if (name === 'package-lock.json' || name === 'npm-shrinkwrap.json') {
    let j;
    try { j = JSON.parse(text); } catch { return []; }
    if (j.packages) {
      for (const [key, v] of Object.entries(j.packages)) {
        if (!key || v.link) continue;
        add('npm', v.name || key.split('node_modules/').pop(), v.version);
      }
    } else {
      const walk = (deps) => {
        for (const [pkg, v] of Object.entries(deps || {})) {
          add('npm', pkg, v.version);
          walk(v.dependencies);
        }
      };
      walk(j.dependencies);
    }
  } else if (name === 'requirements.txt') {
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.split('#')[0].split(';')[0].trim();
      const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([0-9][^\s,]*)$/.exec(line);
      if (m) add('PyPI', m[1].toLowerCase(), m[2]);
    }
  } else if (name === 'composer.lock') {
    let j;
    try { j = JSON.parse(text); } catch { return []; }
    for (const p of [...(j.packages || []), ...(j['packages-dev'] || [])]) add('Packagist', p.name, String(p.version || '').replace(/^v/, ''));
  }
  return [...out.values()];
}

/* ---------- Skor CVSS v3 ---------- */

export function cvss3(vector) {
  const m = {};
  for (const part of String(vector).split('/')) {
    const [k, v] = part.split(':');
    m[k] = v;
  }
  if (!m.AV || !m.AC || !m.PR || !m.UI || !m.S || !m.C || !m.I || !m.A) return null;
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const AC = { L: 0.77, H: 0.44 }[m.AC];
  const changed = m.S === 'C';
  const PR = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const UI = { N: 0.85, R: 0.62 }[m.UI];
  const cia = { H: 0.56, L: 0.22, N: 0 };
  const iss = 1 - (1 - cia[m.C]) * (1 - cia[m.I]) * (1 - cia[m.A]);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  const expl = 8.22 * AV * AC * PR * UI;
  if (![AV, AC, PR, UI].every(Number.isFinite) || impact <= 0) return 0;
  const raw = changed ? Math.min(1.08 * (impact + expl), 10) : Math.min(impact + expl, 10);
  return Math.ceil(raw * 10) / 10;
}

function severityOf(v) {
  const label = String(v.database_specific?.severity || '').toUpperCase();
  if (label) return { CRITICAL: 10, HIGH: 8, MODERATE: 5, MEDIUM: 5, LOW: 2 }[label] ?? 5;
  for (const s of v.severity || []) {
    if (/^CVSS:3/.test(s.score || '')) {
      const sc = cvss3(s.score);
      if (sc != null) return sc;
    }
  }
  return 5;
}

/* ---------- Klien OSV ---------- */

async function post(fetchImpl, url, body, timeout) {
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeout),
  });
  if (!res.ok) throw new Error(`OSV ${res.status}`);
  return res.json();
}

async function fetchDetail(fetchImpl, id, timeout) {
  if (details.has(id)) return details.get(id);
  const res = await fetchImpl(`${BASE}/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(timeout) });
  if (!res.ok) throw new Error(`OSV ${res.status}`);
  const v = await res.json();
  const fixed = {};
  for (const a of v.affected || []) {
    const key = `${a.package?.ecosystem}|${a.package?.name}`;
    for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) (fixed[key] ||= []).push(e.fixed);
  }
  const d = { id: v.id, summary: v.summary || '', score: severityOf(v), fixed, aliases: v.aliases || [] };
  details.set(id, d);
  return d;
}

export async function lookup(deps, { fetchImpl = fetch, timeout = 15000 } = {}) {
  const now = Date.now();
  const todo = deps.filter((d) => {
    const c = cache.get(`${d.ecosystem}|${d.name}|${d.version}`);
    return !c || now - c.at > TTL;
  });
  for (let i = 0; i < todo.length; i += 500) {
    const chunk = todo.slice(i, i + 500);
    const r = await post(fetchImpl, `${BASE}/v1/querybatch`, {
      queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })),
    }, timeout);
    chunk.forEach((d, j) => {
      cache.set(`${d.ecosystem}|${d.name}|${d.version}`, { at: now, ids: (r.results?.[j]?.vulns || []).map((x) => x.id) });
    });
  }
  const hits = [];
  const ids = new Set();
  for (const d of deps) {
    const c = cache.get(`${d.ecosystem}|${d.name}|${d.version}`);
    if (c?.ids.length) {
      hits.push({ dep: d, ids: c.ids });
      c.ids.forEach((x) => ids.add(x));
    }
  }
  const list = [...ids].slice(0, 200);
  for (let i = 0; i < list.length; i += 8)
    await Promise.all(list.slice(i, i + 8).map((id) => fetchDetail(fetchImpl, id, timeout).catch(() => null)));
  return hits;
}

const lvlOf = (score) => (score >= 7 ? 2 : score >= 4 ? 1 : 0);

export function toFindings(hits) {
  const out = [];
  for (const { dep, ids } of hits) {
    const ds = ids.map((id) => details.get(id)).filter(Boolean);
    const worst = ds.reduce((m, d) => Math.max(m, d.score), ds.length ? 0 : 5);
    const shown = ids.slice(0, 3).join(', ');
    const fixed = [...new Set(ds.flatMap((d) => d.fixed[`${dep.ecosystem}|${dep.name}`] || []))];
    const fix = fixed.length
      ? `Perbarui ${dep.name} ke versi ${fixed.slice(-1)[0]} atau lebih baru, lalu jalankan ulang audit.`
      : `Belum ada versi perbaikan yang tercatat di OSV untuk ${dep.name}. Pertimbangkan alternatif atau mitigasi.`;
    out.push(F(lvlOf(worst), 'cve', `${dep.name}@${dep.version}: ${ids.length} kerentanan (${shown}${ids.length > 3 ? ', ...' : ''}), skor tertinggi ${worst.toFixed(1)}`, fix));
  }
  return out;
}

/** Audit satu berkas dependensi. Tidak melempar error: kalau OSV tidak terjangkau, hasilnya satu temuan info. */
export async function auditDepsFile(abs, name, opts = {}) {
  try {
    const text = await fs.readFile(abs, 'utf8');
    const deps = parseDeps(name, text);
    if (!deps.length) return [];
    return toFindings(await lookup(deps, opts));
  } catch {
    return [F(0, 'cve-skip', 'Pemeriksaan CVE dilewati (api.osv.dev tidak terjangkau)')];
  }
}

export const _test = { cache, details };
