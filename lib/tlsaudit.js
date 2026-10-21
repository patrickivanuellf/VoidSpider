/* Audit TLS pasif: versi protokol, cipher lemah, rantai sertifikat, ukuran kunci, dan masa berlaku.
   Hanya melakukan handshake TLS biasa ke host milikmu, tanpa mengirim data aplikasi. */

import tls from 'node:tls';
import net from 'node:net';
import { F } from './rules.js';

const LEGACY = 'ALL:@SECLEVEL=0';

function handshake(host, port, opts = {}, timeout = 8000) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    let s;
    try {
      s = tls.connect({ host, port, ...(net.isIP(host) ? {} : { servername: host }), rejectUnauthorized: false, timeout, ...opts }, () => {
        const info = {
          ok: true,
          protocol: s.getProtocol(),
          cipher: s.getCipher(),
          cert: s.getPeerCertificate(true),
          authorized: s.authorized,
          authError: s.authorizationError ? String(s.authorizationError.message || s.authorizationError) : null,
        };
        s.end();
        finish(info);
      });
    } catch (e) {
      // Opsi (mis. cipher) tidak didukung OpenSSL lokal: hasilnya tidak bisa disimpulkan
      return finish({ ok: false, error: String(e.message || e), code: e.code });
    }
    s.on('error', (e) => finish({ ok: false, error: String(e.message || e), code: e.code }));
    s.on('close', () => finish({ ok: false, error: 'koneksi ditutup' }));
    s.on('timeout', () => { s.destroy(); finish({ ok: false, error: 'timeout' }); });
  });
}

// Galat dari sisi lokal (OpenSSL kita sendiri tidak punya cipher itu) berarti hasilnya tidak bisa disimpulkan.
const localLimit = (r) => !r.ok && /no cipher match|no protocols available|unsupported protocol|wrong version/i.test(r.error || '') && !/alert/i.test(r.error || '');

const daysLeft = (cert) => (new Date(cert.valid_to) - Date.now()) / 86400000;

function chainFindings(host, info, label = '') {
  const out = [];
  const pre = label ? `${label}: ` : '';
  const c = info.cert;
  if (!c || !c.valid_to) return out;

  const d = daysLeft(c);
  if (d < 0) out.push(F(2, 'tls', `${pre}Sertifikat TLS sudah kedaluwarsa`));
  else if (d < 14) out.push(F(2, 'tls', `${pre}Sertifikat TLS berakhir dalam kurang dari 14 hari`));
  else if (d < 30) out.push(F(1, 'tls', `${pre}Sertifikat TLS berakhir dalam kurang dari 30 hari`));

  const err = info.authError || '';
  if (/SELF.SIGNED|self.signed/i.test(err)) out.push(F(2, 'tls-chain', `${pre}Sertifikat self-signed (browser akan menolak)`));
  else if (/unable to verify the first certificate|UNABLE_TO_VERIFY_LEAF_SIGNATURE|unable to get local issuer/i.test(err))
    out.push(F(1, 'tls-chain', `${pre}Rantai sertifikat tidak lengkap (sertifikat intermediate hilang)`));
  if (tls.checkServerIdentity(host, c)) out.push(F(2, 'tls-chain', `${pre}Nama pada sertifikat tidak cocok dengan host ${host}`));

  if (c.bits && !c.asn1Curve && c.bits < 2048) out.push(F(1, 'tls-key', `${pre}Kunci RSA hanya ${c.bits} bit`));

  // Sertifikat intermediate yang mendekati kedaluwarsa
  let cur = c;
  for (let i = 0; i < 5 && cur.issuerCertificate && cur.issuerCertificate !== cur; i++) {
    cur = cur.issuerCertificate;
    if (cur.valid_to && daysLeft(cur) < 30 && daysLeft(cur) >= -3650 && cur.issuerCertificate !== cur)
      out.push(F(daysLeft(cur) < 0 ? 2 : 1, 'tls', `${pre}Sertifikat intermediate (${cur.subject?.CN || 'CA'}) hampir atau sudah kedaluwarsa`));
  }
  return out;
}

export async function auditTls(host, port = 443) {
  const out = [];
  const main = await handshake(host, port);
  if (!main.ok) return out;
  out.push(...chainFindings(host, main));

  for (const v of ['TLSv1', 'TLSv1.1']) {
    const r = await handshake(host, port, { minVersion: v, maxVersion: v, ciphers: LEGACY });
    if (r.ok) out.push(F(1, 'tls-proto', `Server masih menerima ${v.replace('TLSv', 'TLS ')} (usang)`));
  }
  const t13 = await handshake(host, port, { minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' });
  if (!t13.ok && !localLimit(t13)) out.push(F(0, 'tls-proto', 'Server tidak mendukung TLS 1.3'));

  for (const [label, ciphers] of [['3DES', 'DES-CBC3-SHA:@SECLEVEL=0'], ['NULL', 'NULL-SHA:@SECLEVEL=0'], ['RC4', 'RC4-SHA:@SECLEVEL=0']]) {
    const r = await handshake(host, port, { maxVersion: 'TLSv1.2', ciphers });
    if (r.ok) out.push(F(1, 'tls-cipher', `Server menerima cipher lemah ${label}`));
  }
  return out;
}

/** Cek masa berlaku dan kecocokan nama sertifikat untuk daftar subdomain milikmu. */
export async function auditSubCerts(hosts, { limit = 20, port = 443 } = {}) {
  const out = [];
  const list = hosts.slice(0, limit);
  for (let i = 0; i < list.length; i += 5) {
    const batch = await Promise.all(list.slice(i, i + 5).map(async (h) => ({ h, r: await handshake(h, port, {}, 6000) })));
    for (const { h, r } of batch) if (r.ok) out.push(...chainFindings(h, r, h));
  }
  return out;
}

export const _test = { handshake, chainFindings };
