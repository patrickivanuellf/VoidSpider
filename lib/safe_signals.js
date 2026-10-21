/* Sinyal pengujian AMAN (non-destruktif) untuk Laba-laba.
   - Tidak mengeksekusi RCE, tidak dump DB, tidak takeover akun.
   - Hanya menambahkan temuan; tidak menonaktifkan fitur lain.
   - Rate terbatas: max beberapa probe per siklus. */

import { F } from './rules.js';

const XSS_PROBE = '<llb-xss-test>';
const SQL_PROBE = "'\"--";

/** Apakah body mengindikasikan error SQL. */
function sqlError(body) {
  return /SQLSTATE|sql syntax|mysql_fetch|pg_query|ORA-\d{5}|Unclosed quotation mark|syntax error at or near/i.test(body || '');
}

/**
 * Probe aman pada URL yang sudah dalam origin yang sama.
 * @param {string} pageUrl URL halaman saat ini
 * @param {(url: string) => Promise<{status:number, body:string, ct?:string}>} getter fungsi GET (punya timeout/limit yang sama dengan crawler)
 * @param {{ maxProbes?: number }} opts
 */
export async function safeSignalsForPage(pageUrl, getter, opts = {}) {
  const maxProbes = opts.maxProbes ?? 2;
  const findings = [];
  let used = 0;

  let u;
  try {
    u = new URL(pageUrl);
  } catch {
    return findings;
  }

  // 1) XSS reflection: tambah/ ganti param q
  if (used < maxProbes) {
    used++;
    const ux = new URL(u.href);
    ux.searchParams.set('q', XSS_PROBE);
    try {
      const r = await getter(ux.href);
      const body = r?.body || '';
      if (body.includes(XSS_PROBE) && !body.includes('&lt;llb-xss-test') && !body.includes('&lt;llb-xss')) {
        findings.push(
          F(
            1,
            'safe-xss-reflect',
            `Input dipantulkan tanpa encoding HTML yang jelas (${ux.pathname}?q=...)`,
            'Lakukan output encoding sesuai konteks HTML/attr/JS dan aktifkan CSP.'
          )
        );
      }
    } catch {
      /* abaikan gagal probe */
    }
  }

  // 2) SQL error signal
  if (used < maxProbes) {
    used++;
    const us = new URL(u.href);
    us.searchParams.set('id', SQL_PROBE);
    try {
      const r = await getter(us.href);
      const body = r?.body || '';
      if (sqlError(body)) {
        findings.push(
          F(
            2,
            'safe-sql-error',
            `Indikasi SQL error setelah input uji non-destruktif pada ${us.pathname}`,
            'Gunakan prepared statement / parameter binding. Verifikasi manual di staging.'
          )
        );
      }
    } catch {
      /* abaikan */
    }
  }

  return findings;
}

/** Batasi: hanya jalankan di root + N halaman berparameter per siklus. */
export function shouldProbe(node, { isRoot, probedCount, maxPages = 5 }) {
  if (isRoot) return true;
  if (probedCount >= maxPages) return false;
  try {
    const u = new URL(node.url);
    if ([...u.searchParams.keys()].length > 0) return true;
  } catch {
    return false;
  }
  // beberapa halaman form/login
  if (/login|search|cari|q=/i.test(node.path || node.url || '')) return true;
  return false;
}
