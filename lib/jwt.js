/* Pemeriksaan JWT pasif: hanya men-decode bagian header dan payload (base64url), TIDAK memverifikasi
   tanda tangan dan tidak butuh secret apa pun. Nilai token itu sendiri tidak pernah dikembalikan. */

import { F } from './rules.js';

const JWT_RE = /\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
const SENSITIVE_CLAIM = /password|secret|ssn|card[_-]?number|pin\b/i;

export function decodeJwtPart(b64url) {
  try {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
    const j = JSON.parse(Buffer.from(b64 + pad, 'base64').toString('utf8'));
    return j && typeof j === 'object' ? j : null;
  } catch { return null; }
}

function findingsFor(token) {
  const parts = token.split('.');
  if (parts.length < 2) return [];
  const header = decodeJwtPart(parts[0]);
  if (!header || typeof header.alg === 'undefined') return [];
  const payload = decodeJwtPart(parts[1]) || {};
  const out = [];
  if (/^none$/i.test(String(header.alg))) out.push(F(2, 'jwt-none', 'Token JWT memakai alg:none (tanda tangan tidak diverifikasi)'));
  if (payload.exp === undefined) out.push(F(1, 'jwt-noexp', 'Token JWT tidak memiliki klaim exp (tidak pernah kedaluwarsa)'));
  else if (Number.isFinite(payload.exp) && payload.exp * 1000 - Date.now() > 10 * 365 * 86400000) out.push(F(0, 'jwt-longexp', 'Token JWT berumur sangat panjang (lebih dari 10 tahun)'));
  const sens = Object.keys(payload).filter((k) => SENSITIVE_CLAIM.test(k));
  if (sens.length) out.push(F(1, 'jwt-claim', `Klaim JWT memuat nama yang tampak sensitif: ${sens.slice(0, 4).join(', ')}`));
  return out;
}

/** Pindai teks untuk JWT dan kembalikan temuan unik (tidak berulang untuk token yang sama persis). */
export function jwtScan(text, { max = 6 } = {}) {
  if (!text) return [];
  const seen = new Set();
  const out = [];
  let m;
  let n = 0;
  JWT_RE.lastIndex = 0;
  while ((m = JWT_RE.exec(text)) && n < max) {
    n++;
    for (const f of findingsFor(m[0])) {
      const k = `${f.rule}|${f.text}`;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(f);
    }
  }
  return out;
}
