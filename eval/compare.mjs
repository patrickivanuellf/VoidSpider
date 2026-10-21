// Menggabungkan hasil ours.json, gitleaks.json, semgrep.json terhadap ground-truth.json yang sama,
// menghitung precision/recall/F1/FPR per alat, lalu menulis tabel markdown.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const gt = JSON.parse(fs.readFileSync(path.join(DIR, 'ground-truth.json'), 'utf8'));
const read = (f) => { try { return JSON.parse(fs.readFileSync(path.join(DIR, 'results', f), 'utf8')); } catch { return null; } };

const ours = read('ours.json');
const gitleaks = read('gitleaks.json') || [];
const semgrep = read('semgrep.json');

const flaggedByGitleaks = new Set(gitleaks.map((l) => path.relative(path.join(DIR, 'corpus'), l.File || l.file || '')));
const flaggedBySemgrep = new Set((semgrep?.results || []).map((r) => r.path.replace(/^eval\/corpus\//, '')));
const ourFlagged = new Map(ours.rows.map((r) => [r.file, r.flagged]));

// Cakupan tiap alat: gitleaks hanya "secrets"+"jwt" (ia pemindai rahasia), semgrep hanya kategori yang
// aturan lokalnya tulis (iac, taint, webshell, secrets-generik). Kami laporkan N/A untuk kategori di luar cakupan,
// bukan skor nol, karena itu bukan kegagalan alat melainkan memang bukan tujuannya.
const SCOPE = {
  'laba-laba-pemindai': ['secrets', 'jwt', 'webshell', 'taint', 'iac'],
  gitleaks: ['secrets', 'jwt'],
  semgrep: ['taint', 'webshell', 'iac'],
};

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
  const f1 = precision != null && recall != null && precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : null;
  const fpr = fp + tn ? fp / (fp + tn) : null;
  return { tp, fp, fn, tn, precision, recall, f1, fpr };
}

function evalTool(name, flaggedSet) {
  const scope = SCOPE[name];
  const rows = gt.filter((r) => scope.includes(r.category)).map((r) => ({ ...r, flagged: flaggedSet.has(r.file) }));
  return metrics(rows);
}

const results = {
  'laba-laba-pemindai': evalTool('laba-laba-pemindai', new Set([...ourFlagged].filter(([, v]) => v).map(([k]) => k))),
  gitleaks: evalTool('gitleaks', flaggedByGitleaks),
  semgrep: evalTool('semgrep', flaggedBySemgrep),
};

const pct = (v) => (v == null ? 'n/a' : (v * 100).toFixed(1) + '%');
const lines = [
  '| Alat | Cakupan kategori | TP | FP | FN | TN | Precision | Recall | F1 | FPR |',
  '|---|---|---|---|---|---|---|---|---|---|',
];
for (const [name, m] of Object.entries(results)) {
  lines.push(`| ${name} | ${SCOPE[name].join(', ')} | ${m.tp} | ${m.fp} | ${m.fn} | ${m.tn} | ${pct(m.precision)} | ${pct(m.recall)} | ${pct(m.f1)} | ${pct(m.fpr)} |`);
}
const table = lines.join('\n');
console.log(table);
fs.writeFileSync(path.join(DIR, 'results', 'comparison.md'), `# Perbandingan pada korpus pengembangan (eval/corpus, n=${gt.length})\n\n${table}\n`);
fs.writeFileSync(path.join(DIR, 'results', 'comparison.json'), JSON.stringify(results, null, 1));
