/* Deteksi kredensial generik yang tidak cocok pola spesifik (SECRETS di rules.js), lewat entropi.
   Sengaja dibuat ketat (kata kunci wajib berdekatan, harus campuran huruf besar/kecil/angka, bukan
   hash heksadesimal atau UUID) supaya tidak mengulang kesalahan pola "sk-" yang terlalu longgar.
   Nilai asli tidak pernah dikembalikan, hanya konteks kata kunci, panjang, dan entropi. */

import { F } from './rules.js';

const KEYWORD = /api[_-]?key|secret|token|auth(?:orization)?|credential|password|access[_-]?key|client[_-]?secret|private[_-]?key/gi;
const CANDIDATE = /["'`]([A-Za-z0-9+/._-]{20,100})["'`]/;
const ALL_HEX_OR_DASH = /^[0-9a-fA-F-]+$/;
const ALL_DIGIT = /^[0-9]+$/;

function entropy(s) {
  const freq = new Map();
  for (const c of s) freq.set(c, (freq.get(c) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function plausible(val) {
  if (ALL_HEX_OR_DASH.test(val) || ALL_DIGIT.test(val)) return false; // hash, commit SHA, UUID, nomor
  if (new Set(val).size < 6) return false; // variasi karakter terlalu sedikit
  if (!/[A-Z]/.test(val) || !/[a-z]/.test(val) || !/[0-9]/.test(val)) return false; // harus campuran, seperti kunci asli
  return entropy(val) >= 3.2;
}

/** Cari "kata kunci sensitif" diikuti nilai berkutip yang tampak acak dalam jarak dekat. */
export function genericSecretFindings(text, { max = 5 } = {}) {
  if (!text) return [];
  const out = [];
  const seen = new Set();
  let km;
  KEYWORD.lastIndex = 0;
  while ((km = KEYWORD.exec(text)) && out.length < max) {
    const window = text.slice(km.index, km.index + 160);
    const cm = CANDIDATE.exec(window);
    if (!cm || !plausible(cm[1])) continue;
    const key = `${km[0].toLowerCase()}|${cm[1].length}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(F(1, 'secret-generic', `Nilai mirip kredensial setelah kata kunci "${km[0]}" (panjang ${cm[1].length}, entropi ${entropy(cm[1]).toFixed(1)})`));
  }
  return out;
}

export const _test = { entropy, plausible };
