// Menjalankan auditFile() -- fungsi produksi yang sama persis dipakai server.js untuk mode berkas --
// pada tiap berkas korpus, dibandingkan dengan ground-truth.json, lalu menghitung precision/recall/F1/FPR.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditFile } from '../lib/filescan.js';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(DIR, 'corpus');
const gt = JSON.parse(fs.readFileSync(path.join(DIR, 'ground-truth.json'), 'utf8'));
const noIgnore = () => false;

async function detect(file) {
  const abs = path.join(ROOT, file);
  const name = path.basename(file);
  const st = await fs.promises.lstat(abs);
  const r = await auditFile({ abs, rel: file, name, st, maxBytes: 2_000_000, isIgnored: noIgnore });
  return r.findings;
}

function metrics(rows) {
  let tp = 0, fp = 0, fn = 0, tn = 0;
  for (const r of rows) {
    if (r.expected_vulnerable && r.flagged) tp++;
    else if (!r.expected_vulnerable && r.flagged) fp++;
    else if (r.expected_vulnerable && !r.flagged) fn++;
    else tn++;
  }
  const precision = tp + fp ? tp / (tp + fp) : null;
  const recall = tp + fn ? tp / (tp + fn) : null;
  const f1 = precision && recall ? (2 * precision * recall) / (precision + recall) : null;
  const fpr = fp + tn ? fp / (fp + tn) : null;
  return { tp, fp, fn, tn, precision, recall, f1, fpr };
}

const t0 = Date.now();
const rows = [];
for (const row of gt) {
  const findings = await detect(row.file);
  const flagged = findings.some((f) => f.lvl >= 1);
  rows.push({ ...row, flagged, findings: findings.map((f) => `${f.rule}:${f.lvl}`) });
}
const ms = Date.now() - t0;

const byCategory = {};
for (const r of rows) (byCategory[r.category] ||= []).push(r);

const out = {
  tool: 'laba-laba-pemindai',
  ms,
  overall: metrics(rows),
  byCategory: Object.fromEntries(Object.entries(byCategory).map(([k, v]) => [k, metrics(v)])),
  rows,
};
fs.writeFileSync(path.join(DIR, 'results', 'ours.json'), JSON.stringify(out, null, 1));
console.log(`laba-laba-pemindai: ${ms} ms, overall`, out.overall);
for (const [k, v] of Object.entries(out.byCategory)) console.log(`  ${k}:`, v);

const wrong = rows.filter((r) => r.expected_vulnerable !== r.flagged);
if (wrong.length) {
  console.log('\nMeleset:');
  for (const r of wrong) console.log(`  ${r.expected_vulnerable ? 'FN' : 'FP'} ${r.file}`, r.findings);
}
