/* Memuat probe path web tambahan dari berkas JSON, supaya daftar path sensitif bisa diperluas
   tanpa mengubah kode. Bentuknya sama dengan PROBES bawaan di lib/rules.js. */

import fs from 'node:fs';
import path from 'node:path';

export function loadUserProbes(dir = process.env.PROBES_DIR || path.join(process.cwd(), 'rules', 'probes')) {
  let files = [];
  try { files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')); } catch { return []; }
  const out = [];
  for (const f of files) {
    let items;
    try { items = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')); } catch { continue; }
    for (const it of Array.isArray(items) ? items : [items]) {
      if (!it.path || !it.text) continue;
      let bodyRe;
      try { bodyRe = it.bodyMatch ? new RegExp(it.bodyMatch, it.flags || '') : null; } catch { continue; }
      const ctRe = it.ctMatch ? new RegExp(it.ctMatch, 'i') : null;
      out.push({
        p: it.path,
        t: String(it.text),
        lvl: [0, 1, 2].includes(it.lvl) ? it.lvl : 1,
        ok: (r) => (!bodyRe || bodyRe.test(r.body)) && (!ctRe || ctRe.test(r.ct)),
      });
    }
  }
  return out;
}
