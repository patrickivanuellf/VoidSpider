/* Keluaran SARIF 2.1.0 supaya hasil audit bisa diunggah ke GitHub Code Scanning. */

import crypto from 'node:crypto';

const LEVEL = ['note', 'warning', 'error'];

export function toSarif(items, { mode, target, version = '2.0.0' } = {}) {
  const rules = new Map();
  const results = [];
  for (const { path, f } of items) {
    const prev = rules.get(f.rule);
    if (!prev) rules.set(f.rule, { id: f.rule, name: f.rule, shortDescription: { text: f.rule }, help: { text: f.fix || f.rule }, defaultConfiguration: { level: LEVEL[f.lvl] } });
    else if (f.lvl > LEVEL.indexOf(prev.defaultConfiguration.level)) prev.defaultConfiguration.level = LEVEL[f.lvl];

    const line = /\(baris (\d+)\)/.exec(f.text)?.[1];
    const physicalLocation = { artifactLocation: mode === 'file' ? { uri: path, uriBaseId: '%SRCROOT%' } : { uri: path } };
    if (line) physicalLocation.region = { startLine: Number(line) };
    results.push({
      ruleId: f.rule,
      level: LEVEL[f.lvl],
      message: { text: f.fix ? `${f.text}. Saran: ${f.fix}` : f.text },
      locations: [{ physicalLocation }],
      partialFingerprints: { 'labaLaba/v1': crypto.createHash('sha1').update(`${f.rule}|${path}|${f.text}`).digest('hex') },
    });
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'laba-laba-pemindai', version, informationUri: 'https://github.com/patrickivanuellf', rules: [...rules.values()] } },
      invocations: [{ executionSuccessful: true, properties: { target, mode } }],
      results,
    }],
  };
}
