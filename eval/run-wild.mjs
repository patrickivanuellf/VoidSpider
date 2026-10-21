// Validasi independen: menjalankan auditFile() pada korpus webshell publik (tennc/webshell) yang
// TIDAK PERNAH dipakai untuk menyetel aturan deteksi. Semua berkas di sini diasumsikan positif (webshell asli)
// -- ini mengukur RECALL di alam liar, bukan precision (korpus ini tidak punya sampel negatif).
import fs from 'node:fs';
import path from 'node:path';
import { auditFile } from '../lib/filescan.js';

const ROOT = process.argv[2] || '/tmp/webshell-wild';
const EXTS = new Set(['php', 'phtml', 'php3', 'php4', 'php5', 'php7']);
const noIgnore = () => false;

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === '.git') continue;
    const abs = path.join(dir, e.name);
    if (e.isDirectory()) walk(abs, out);
    else if (EXTS.has((e.name.split('.').pop() || '').toLowerCase())) out.push(abs);
  }
  return out;
}

const files = walk(ROOT);
let flagged = 0, byRule = {};
const missed = [];
for (const abs of files) {
  const st = await fs.promises.lstat(abs);
  const name = path.basename(abs);
  const r = await auditFile({ abs, rel: abs, name, st, maxBytes: 2_000_000, isIgnored: noIgnore });
  const hit = r.findings.filter((f) => f.lvl >= 1);
  if (hit.length) {
    flagged++;
    for (const f of hit) byRule[f.rule] = (byRule[f.rule] || 0) + 1;
  } else missed.push(abs);
}
console.log(`Total berkas PHP di koleksi: ${files.length}`);
console.log(`Terdeteksi (lvl>=1): ${flagged} (recall = ${((flagged / files.length) * 100).toFixed(1)}%)`);
console.log('Berdasarkan aturan (boleh tumpang tindih per berkas):', byRule);
fs.writeFileSync(
  path.join(path.dirname(new URL(import.meta.url).pathname), 'results', 'wild-webshell.json'),
  JSON.stringify({ total: files.length, flagged, recall: flagged / files.length, byRule, missedSample: missed.slice(0, 15).map((f) => path.relative(ROOT, f)) }, null, 1)
);
