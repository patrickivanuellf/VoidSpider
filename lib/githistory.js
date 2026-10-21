/* Cari kunci rahasia yang pernah ter-commit di riwayat Git, walaupun sudah dihapus dari berkas sekarang.
   Memakai git sebagai proses terpisah dengan argumen tetap (tanpa shell) dan hanya membaca.
   Nilai rahasia tidak pernah dikembalikan: hanya jenis, hash commit, dan path. */

import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { F, SECRETS, secretMatch } from './rules.js';

const SKIP = /(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|\.min\.js|\.map|\.svg)$/i;

export function hasGit(root) {
  try { return fs.statSync(path.join(root, '.git')).isDirectory(); } catch { return false; }
}

export function gitHead(root) {
  return new Promise((resolve) => {
    execFile('git', ['-C', root, 'rev-parse', 'HEAD'], { timeout: 8000 }, (err, out) => resolve(err ? null : String(out).trim()));
  });
}

export function scanGitHistory(root, { maxCommits = 300, maxBytes = 20 * 1024 * 1024 } = {}) {
  return new Promise((resolve) => {
    const args = ['-C', root, 'log', '--all', `--max-count=${maxCommits}`, '-p', '-U0', '--no-color', '--no-ext-diff', '--diff-filter=AM', '--format=@@C %h'];
    let child;
    try { child = spawn('git', args, { stdio: ['ignore', 'pipe', 'ignore'] }); } catch { return resolve([]); }
    const found = new Map();
    let commit = '';
    let file = '';
    let read = 0;
    let buf = '';
    let settled = false;
    const done = () => {
      if (settled) return;
      settled = true;
      resolve([...found.values()]);
    };
    const line = (l) => {
      if (l.startsWith('@@C ')) { commit = l.slice(4).trim(); return; }
      if (l.startsWith('+++ ')) { file = l.slice(4).replace(/^b\//, ''); return; }
      if (!l.startsWith('+') || l.startsWith('+++') || !file || SKIP.test(file)) return;
      const text = l.slice(1, 2001);
      for (const entry of SECRETS) {
        const [, name, lvl, fileOnly] = entry;
        if (fileOnly || !secretMatch(entry, text)) continue;
        const key = `${name}|${file}`;
        if (!found.has(key)) found.set(key, F(lvl === 1 ? 1 : 2, 'git-secret', `${name} pernah ter-commit di ${commit} (${file})`));
      }
    };
    child.stdout.on('data', (d) => {
      read += d.length;
      buf += d.toString('utf8');
      const parts = buf.split('\n');
      buf = parts.pop();
      parts.forEach(line);
      if (read > maxBytes) { child.kill(); done(); }
    });
    child.on('error', done);
    child.on('close', () => { if (buf) line(buf); done(); });
    setTimeout(() => { child.kill(); done(); }, 60000).unref();
  });
}
