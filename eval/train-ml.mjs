#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { trainFromCorpus, saveModel } from '../lib/ml_malware.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), 'corpus');
const result = trainFromCorpus(root);
console.log(JSON.stringify(result, null, 2));
if (result.ok) {
  const out = path.join(path.dirname(fileURLToPath(import.meta.url)), 'results', 'ml-malware-model.json');
  saveModel(out, result.model);
  console.log('Model disimpan:', out);
}
