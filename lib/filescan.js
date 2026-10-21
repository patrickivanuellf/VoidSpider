/* Audit statis untuk berkas dan folder lokal. Hanya membaca, tidak mengeksekusi apa pun,
   tidak mengikuti symlink, dan tidak pernah mengembalikan nilai rahasia yang ditemukan. */

import fs from 'node:fs/promises';
import crypto from 'node:crypto';
import path from 'node:path';
import * as cheerio from 'cheerio';
import {
  F, INJ, INVISIBLE_TAG, BIDI, ZEROWIDTH, findSecrets, CODE_RULES, SENSITIVE,
  EXEC_EXT, DOC_EXT, DOUBLE_EXT,
} from './rules.js';
import { jwtScan } from './jwt.js';
import { genericSecretFindings } from './entropy.js';
import { malwareFindings, binaryPayloadFindings } from './malware.js';
import { mlMalwareFindings, loadModel } from './ml_malware.js';
try {
  loadModel(new URL('../eval/results/ml-malware-model.json', import.meta.url));
} catch { /* model default */ }
import { taintFindings } from './ast.js';

export const SKIP_DIRS = new Set(['node_modules', '__MACOSX']);
export const VCS_DIRS = new Set(['.git', '.svn', '.hg']);

const DOCS = new Set(['md', 'markdown', 'txt', 'rst']);
const LOCKS = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'npm-shrinkwrap.json'];
const win = process.platform === 'win32';

/* ---------- .gitignore sederhana ---------- */

const globToRe = (g) =>
  g
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\u0000/g, '.*')
    .replace(/\?/g, '[^/]');

export async function loadIgnore(root) {
  let lines = [];
  try {
    lines = (await fs.readFile(path.join(root, '.gitignore'), 'utf8'))
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#') && !l.startsWith('!'));
  } catch { /* tidak ada .gitignore */ }
  const res = lines.map((l) => {
    const anchored = l.startsWith('/') || l.replace(/\/$/, '').includes('/');
    const g = l.replace(/^\//, '').replace(/\/$/, '');
    return new RegExp((anchored ? '^' : '(?:^|/)') + globToRe(g) + '(?:/|$)');
  });
  return (rel) => res.some((re) => re.test(rel));
}

/* ---------- Temuan tingkat folder ---------- */

export function auditDir(name, st, names, { isRoot }) {
  const f = [];
  if (VCS_DIRS.has(name) && !isRoot)
    f.push(F(1, 'file-git', `Folder ${name} ikut ada (jangan sampai ter-deploy ke server publik)`));
  if (!win && st.mode & 0o002) f.push(F(1, 'file-perm', 'Folder dapat ditulis oleh siapa saja (world-writable)'));
  if (names && names.includes('package.json') && !names.some((x) => LOCKS.includes(x)))
    f.push(F(0, 'pkg-nolock', 'package.json tanpa lockfile'));
  return f;
}

/* ---------- Temuan khusus tipe ---------- */

function lineOf(text, idx) {
  let n = 1;
  for (let i = 0; i < idx; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

function htmlFindings(text) {
  const f = [];
  let $;
  try { $ = cheerio.load(text); } catch { return f; }

  const bad = [];
  $('script[src],iframe[src],img[src],link[href]').each((_, e) => {
    const v = $(e).attr('src') || $(e).attr('href');
    if (v && /^http:\/\//i.test(v)) bad.push(v);
  });
  if (bad.length) f.push(F(1, 'mixed', `${bad.length} sumber memakai http:// (tanpa enkripsi)`));

  const ext = new Set();
  $('script[src],link[rel~="stylesheet"][href]').each((_, e) => {
    const v = $(e).attr('src') || $(e).attr('href') || '';
    if (/^(?:https?:)?\/\//i.test(v) && !$(e).attr('integrity')) {
      try { ext.add(new URL(v, 'https://x').hostname); } catch { /* abaikan */ }
    }
  });
  if (ext.size) f.push(F(0, 'sri', `Sumber pihak ketiga tanpa SRI: ${[...ext].slice(0, 3).join(', ')}`));

  $('form').each((_, fm) => {
    const form = $(fm);
    if (/^http:\/\//i.test(form.attr('action') || '')) f.push(F(2, 'formhttp', 'Form mengirim data ke alamat http'));
    if (form.find('input[type=password]').length) {
      if (/^get$/i.test(form.attr('method') || 'get')) f.push(F(2, 'pwget', 'Form sandi memakai method GET (sandi masuk ke URL)'));
      const tok = form.find('input[type=hidden]').filter((__, x) => /csrf|token|nonce|authenticity/i.test($(x).attr('name') || '')).length;
      if (!tok) f.push(F(1, 'csrf', 'Form berisi kolom sandi tanpa token CSRF yang terlihat'));
    }
  });

  $('script,style,noscript').remove();
  const hidden = [];
  $('[hidden],[aria-hidden="true"],[style*="display:none"],[style*="display: none"],[style*="visibility:hidden"],[style*="font-size:0"]').each((_, e) => hidden.push($(e).text()));
  $('*').contents().each((_, n) => {
    if (n.type === 'comment') hidden.push(n.data || '');
  });
  if (INJ.test(hidden.join(' '))) f.push(F(2, 'inj-hidden', 'Teks tersembunyi berisi pola prompt injection'));
  return f;
}

function packageFindings(text) {
  const f = [];
  let pkg;
  try { pkg = JSON.parse(text); } catch { return f; }
  const scripts = pkg.scripts || {};
  for (const k of ['preinstall', 'install', 'postinstall', 'prepare']) {
    if (!scripts[k]) continue;
    const risky = /curl|wget|\bsh\s+-c|\bbash\b|eval|node\s+-e|base64|powershell/i.test(String(scripts[k]));
    f.push(F(risky ? 1 : 0, 'pkg-script', `Skrip ${k} berjalan otomatis saat install${risky ? ' dan memuat perintah yang perlu ditinjau' : ''}`));
  }
  let shown = 0;
  for (const group of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    for (const [name, ver] of Object.entries(pkg[group] || {})) {
      if (shown >= 5) break;
      if (/^(?:\*|latest|x|git|github:|https?:)/i.test(String(ver))) {
        f.push(F(1, 'pkg-pin', `Dependensi ${name} tidak dikunci (${String(ver).slice(0, 30)})`));
        shown++;
      }
    }
  }
  return f;
}

function dockerFindings(text) {
  const f = [];
  if (/^\s*FROM\s+\S+:latest\b/im.test(text)) f.push(F(0, 'docker-latest', 'Base image memakai tag :latest'));
  if (!/^\s*USER\s+(?!root\b)\S+/im.test(text)) f.push(F(1, 'docker-root', 'Dockerfile tidak mengatur USER non-root'));
  return f;
}

/* ---------- Audit satu berkas ---------- */

export async function auditFile({ abs, rel, name, st, maxBytes, isIgnored }) {
  const findings = [];
  const ext = (name.includes('.') ? name.split('.').pop() : '').toLowerCase();
  const ignored = isIgnored(rel);
  let sensitive = false;

  for (const [re, text, lvl] of SENSITIVE) {
    if (!re.test(name)) continue;
    sensitive = lvl >= 1;
    if (ignored && lvl >= 1) findings.push(F(0, 'file-sensitive', `${text} (tercantum di .gitignore, pastikan tidak ikut ter-deploy)`));
    else findings.push(F(lvl, 'file-sensitive', text));
    if (!win && lvl >= 1 && st.mode & 0o044 && /^(?:\.env|id_|\.htpasswd|\.git-credentials|\.npmrc|\.pypirc|credentials)/i.test(name))
      findings.push(F(1, 'file-perm', 'Izin berkas rahasia terlalu longgar (terbaca grup/pengguna lain)'));
    break;
  }
  if (!win && st.mode & 0o002) findings.push(F(1, 'file-perm', 'Berkas dapat ditulis oleh siapa saja (world-writable)'));
  if (DOUBLE_EXT.test(name)) findings.push(F(2, 'file-doubleext', 'Nama berkas berekstensi ganda (teknik penyamaran)'));

  let buf = Buffer.alloc(0);
  let fh;
  try {
    fh = await fs.open(abs, 'r');
    const size = Math.min(st.size, maxBytes);
    buf = Buffer.alloc(size);
    const { bytesRead } = await fh.read(buf, 0, size, 0);
    buf = buf.subarray(0, bytesRead);
  } catch {
    findings.push(F(0, 'unreadable', 'Tidak dapat dibaca (izin ditolak)'));
    return { findings, terms: [], words: 0, isText: false, sha: null };
  } finally {
    await fh?.close();
  }

  const sha = st.size <= maxBytes ? crypto.createHash('sha256').update(buf).digest('hex') : null;
  const hex = buf.subarray(0, 4).toString('hex');
  const execMagic =
    (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) ||
    hex === '7f454c46' ||
    ['cffaedfe', 'cefaedfe', 'feedfacf', 'feedface', 'cafebabe'].includes(hex);

  if (execMagic && DOC_EXT.has(ext)) findings.push(F(2, 'file-masquerade', `Berkas .${ext} sebenarnya biner eksekusi`));
  else if (execMagic || EXEC_EXT.has(ext)) findings.push(F(1, 'file-exec', 'Berkas eksekusi/biner ada di folder'));

  const isText = !execMagic && !buf.subarray(0, 8000).includes(0);
  if (!isText) findings.push(...binaryPayloadFindings(buf, ext));
  if (!isText) return { findings, terms: [], words: 0, isText: false, sha };

  const text = buf.toString('utf8');

  // Rahasia: berkas yang masuk .gitignore diturunkan jadi info, karena memang tidak ikut ter-commit.
  for (const s of findSecrets(text, { file: true })) {
    findings.push(ignored ? F(0, 'secret', `${s.text} (berkas di .gitignore)`) : s);
  }
  for (const s of [...jwtScan(text), ...genericSecretFindings(text)]) {
    findings.push(ignored ? F(0, s.rule, `${s.text} (berkas di .gitignore)`) : s);
  }

  if (INVISIBLE_TAG.test(text)) findings.push(F(2, 'inj-hidden', 'Karakter tag Unicode tak terlihat (teknik menyelundupkan prompt)'));
  if (BIDI.test(text)) findings.push(F(2, 'trojan-source', 'Karakter kontrol bidi di dalam teks (Trojan Source)'));
  if ((text.replace(/^\uFEFF/, '').match(ZEROWIDTH) || []).length > 3) findings.push(F(1, 'zerowidth', 'Banyak karakter tak terlihat (zero-width) di dalam teks'));
  if (INJ.test(text)) findings.push(F(1, 'inj-visible', 'Teks berisi pola perintah ke AI (periksa konteksnya)'));

  const lines = text.split('\n').length;
  const minified = text.length > 5000 && text.length / lines > 400;
  if (!minified) {
    for (const r of CODE_RULES) {
      if (!(r.ext.includes(ext) || (r.ext[0] === '*' && !DOCS.has(ext)))) continue;
      const re = new RegExp(r.re.source, r.re.flags.includes('g') ? r.re.flags : r.re.flags + 'g');
      let m;
      let hits = 0;
      while ((m = re.exec(text)) && hits < 3) {
        findings.push(F(r.lvl, r.rule, `${r.text} (baris ${lineOf(text, m.index)})`));
        hits++;
        if (m[0].length === 0) re.lastIndex++;
      }
    }
  }

  findings.push(...malwareFindings(text, ext));
  findings.push(...mlMalwareFindings(text, rel));
  if (!minified && ['js', 'mjs', 'cjs'].includes(ext)) findings.push(...taintFindings(text));

  if (ext === 'html' || ext === 'htm') findings.push(...htmlFindings(text));
  if (name === 'package.json') findings.push(...packageFindings(text));
  if (/^Dockerfile(?:\..+)?$/i.test(name)) findings.push(...dockerFindings(text));

  const quiet = sensitive || findings.some((f) => f.lvl === 2 || f.rule === 'secret');
  const terms = quiet ? [] : [...new Set(text.toLowerCase().match(/[a-zà-ÿ]{4,14}/g) || [])].slice(0, 40);
  const words = text.split(/\s+/).filter(Boolean).length;
  return { findings, terms, words, isText: true, sha };
}
