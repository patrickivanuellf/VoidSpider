// Mengukur FALSE POSITIVE RATE di kode nyata yang dianggap bersih (bukan korpus buatan sendiri):
// sumber Express.js (library produksi, dipakai jutaan proyek) dan sumber project ini sendiri.
import fs from 'node:fs';
import path from 'node:path';
import { auditFile } from '../lib/filescan.js';

const ROOT = process.argv[2];
const EXTS = new Set(['js', 'mjs', 'cjs']);
const SKIP_DIR = new Set(['node_modules', '.git', 'test', 'tests', 'eval']);
const noIgnore = () => false;

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIR.has(e.name)) continue;
    const abs = path.join(dir, e.name);
    if (e.isDirectory()) walk(abs, out);
    else if (EXTS.has((e.name.split('.').pop() || '').toLowerCase())) out.push(abs);
  }
  return out;
}

const files = walk(ROOT);
let flaggedHigh = 0;
const findings = [];
for (const abs of files) {
  const st = await fs.promises.lstat(abs);
  const name = path.basename(abs);
  const r = await auditFile({ abs, rel: abs, name, st, maxBytes: 2_000_000, isIgnored: noIgnore });
  const hi = r.findings.filter((f) => f.lvl >= 1);
  if (hi.length) { flaggedHigh++; for (const f of hi) findings.push({ file: path.relative(ROOT, abs), ...f }); }
}
console.log(`${ROOT}: ${files.length} berkas .js, ${flaggedHigh} ditandai (lvl>=1) -> FPR permukaan = ${((flaggedHigh / files.length) * 100).toFixed(1)}%`);
for (const f of findings) console.log(`  ${f.file}: [${f.rule}:${f.lvl}] ${f.text}`);
