/* Baseline & drift detection.
   Perubahan v9.1:
   - Whitelist domain CDN/analytics umum supaya tidak jadi temuan kritis (false positive)
   - Domain di whitelist hanya dicatat sebagai info, bukan kritis
*/

import fs from 'node:fs';
import path from 'node:path';
import { F } from './rules.js';

const CODEISH = new Set(['js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'php', 'py', 'rb', 'go', 'java', 'cs', 'sh', 'bash', 'ps1', 'pl', 'cgi']);

/** Domain pihak ketiga yang sangat umum dan hampir selalu sah.
    Tidak diangkat sebagai kritis saat pertama kali muncul di baseline. */
const TRUSTED_THIRD_PARTY = new Set([
  // Google
  'www.google.com', 'google.com', 'www.googletagmanager.com', 'googletagmanager.com',
  'www.google-analytics.com', 'google-analytics.com', 'ssl.google-analytics.com',
  'fonts.googleapis.com', 'fonts.gstatic.com', 'ajax.googleapis.com',
  'www.gstatic.com', 'gstatic.com', 'apis.google.com', 'accounts.google.com',
  'www.youtube.com', 'youtube.com', 'www.youtube-nocookie.com',
  // Cloudflare / CDN
  'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com', 'cdn.jsdelivr.net',
  'static.cloudflareinsights.com', 'challenges.cloudflare.com',
  // Facebook / Meta
  'www.facebook.com', 'facebook.com', 'connect.facebook.net',
  // Lainnya yang sering muncul
  'www.instagram.com', 'platform.twitter.com', 'cdn.syndication.twimg.com',
  'www.linkedin.com', 'snap.licdn.com',
  'www.clarity.ms', 'scripts.clarity.ms',
  'static.hotjar.com', 'script.hotjar.com',
  'js.stripe.com', 'm.stripe.network',
  'www.paypal.com', 'www.paypalobjects.com',
  'player.vimeo.com', 'www.recaptcha.net', 'www.gstatic.com',
]);

function isTrustedHost(hostname) {
  if (!hostname) return false;
  const h = hostname.toLowerCase();
  if (TRUSTED_THIRD_PARTY.has(h)) return true;
  // cocokkan subdomain (mis. region1.google-analytics.com)
  for (const t of TRUSTED_THIRD_PARTY) {
    if (h.endsWith('.' + t) || h === t) return true;
  }
  // pola umum
  if (/\.google(apis|usercontent|syndication)?\.com$/.test(h)) return true;
  if (/\.gstatic\.com$/.test(h)) return true;
  if (/\.youtube\.com$/.test(h)) return true;
  if (/\.cloudflare\.com$/.test(h)) return true;
  if (/\.jsdelivr\.net$/.test(h)) return true;
  if (/\.facebook\.net$/.test(h)) return true;
  return false;
}

export class Baseline {
  constructor(file, { accept = false } = {}) {
    this.file = file;
    this.accept = accept;
    this.fresh = !fs.existsSync(file);
    this.data = this.fresh ? { files: {}, hosts: [], createdAt: null } : JSON.parse(fs.readFileSync(file, 'utf8'));
    this.seenFiles = new Set();
  }

  get learning() { return this.fresh || this.accept; }

  fileDrift(rel, hash) {
    if (!hash) return [];
    this.seenFiles.add(rel);
    const old = this.data.files[rel];
    const ext = (rel.includes('.') ? rel.split('.').pop() : '').toLowerCase();
    const code = CODEISH.has(ext) || /(?:^|\/)\.htaccess$/.test(rel);
    let out = [];
    if (!this.learning) {
      if (!old) out = [F(code ? 1 : 0, 'drift', code ? 'Berkas kode baru sejak baseline (periksa apakah kamu yang membuatnya)' : 'Berkas baru sejak baseline')];
      else if (old.h !== hash) out = [F(code ? 1 : 0, 'drift', `Isi berkas berubah sejak baseline (${old.at.slice(0, 10)})`)];
    }
    if (this.learning || (!old && this.accept)) this.data.files[rel] = { h: hash, at: new Date().toISOString() };
    return out;
  }

  /** Berkas yang ada di baseline tetapi tidak ditemukan lagi. */
  removed() {
    if (this.learning) return [];
    const gone = Object.keys(this.data.files).filter((k) => !this.seenFiles.has(k));
    return gone.length ? [F(0, 'drift', `${gone.length} berkas dari baseline sudah tidak ada (mis. ${gone.slice(0, 3).join(', ')})`)] : [];
  }

  hostDrift(hosts) {
    const out = [];
    const known = new Set(this.data.hosts || []);
    for (const h of hosts) {
      if (known.has(h)) continue;

      if (!this.learning) {
        if (isTrustedHost(h)) {
          // Domain CDN/analytics umum → info saja, bukan kritis
          out.push(F(0, 'drift', `Domain pihak ketiga dikenal (CDN/analytics): ${h}`));
        } else {
          // Domain baru yang tidak dikenal → kritis (kemungkinan injeksi)
          out.push(F(2, 'drift', `Skrip atau iframe dari domain baru sejak baseline: ${h}`));
        }
      }
      if (this.learning) known.add(h);
    }
    if (this.learning) this.data.hosts = [...known].sort();
    return out;
  }

  save() {
    if (!this.learning) return;
    try {
      this.data.createdAt ||= new Date().toISOString();
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      fs.writeFileSync(this.file, JSON.stringify(this.data, null, 1));
      this.fresh = false;
      this.accept = false;
    } catch { /* folder data tidak bisa ditulis: baseline hanya bertahan selama proses berjalan */ }
  }
}

/** Domain pihak ketiga dari skrip dan iframe sebuah halaman, plus indikasi skrip inline yang mencurigakan. */
export function scriptHosts($, origin, base) {
  const hosts = new Set();
  $('script[src],iframe[src]').each((_, e) => {
    try {
      const u = new URL($(e).attr('src'), base);
      if (/^https?:$/.test(u.protocol) && u.origin !== origin) hosts.add(u.hostname);
    } catch { /* abaikan */ }
  });
  return [...hosts];
}

export const SUSPICIOUS_INLINE = /\beval\s*\(|\batob\s*\(|document\.write\s*\(\s*unescape|String\.fromCharCode\s*\((?:\s*\d+\s*,){10,}/;
