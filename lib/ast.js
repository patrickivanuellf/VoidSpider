/* Analisis aliran data (taint) sederhana untuk JavaScript memakai AST (acorn).
   Pelacakan bersifat satu file, tanpa urutan eksekusi: variabel yang pernah menerima input pengguna
   dianggap tercemar, lalu dicek apakah ia sampai ke fungsi berbahaya. Hasilnya petunjuk, bukan bukti. */

import * as acorn from 'acorn';
import * as walk from 'acorn-walk';
import { F } from './rules.js';

const SOURCE = /^(?:req|request|ctx\.request)\.(?:query|body|params|headers|cookies|url|originalUrl)\b|^(?:window\.|document\.)?location\b|^window\.name$|^process\.argv\b|^document\.(?:cookie|referrer)$|^event\.data$/;
const SANITIZER = /^(?:parseInt|parseFloat|Number|Boolean|encodeURIComponent|encodeURI|escape|escapeHtml|escapeHTML|sanitize\w*|DOMPurify\.sanitize|validator\.\w+|path\.basename|\w+\.(?:escape|escapeId|sanitize\w*))$/;
const PASSTHRU = /^(?:String|decodeURIComponent|decodeURI|unescape|JSON\.parse|Buffer\.from|atob)$/;
const JOINERS = /^(?:path\.(?:join|resolve)|String\.raw)$|\.concat$/;
// Properti yang aman sebagai tujuan tulis: browser meng-escape-nya secara otomatis, jadi menulis
// data tercemar ke sini BUKAN propagasi lanjut (mencegah variabel keseluruhan ikut tercemar).
const SAFE_WRITE_PROP = /^(?:textContent|innerText|nodeValue|value)$/;
// Objek framework yang dipakai bersama di banyak tempat (request/response/context). Menulis ke SALAH
// SATU propertinya (mis. `req.pet.name = ...`) tidak boleh membuat identifier ini sendiri (`req`)
// dianggap tercemar untuk SISA berkas -- itu akan mencemari setiap `req.lainnya` lain secara keliru.
const SHARED_OBJECT = /^(?:req|request|res|response|ctx|context|window|document|location|global|globalThis)$/;
const SQLISH = /\b(?:select|insert|update|delete|where|from|values)\b/i;

function dotted(n) {
  if (!n) return null;
  if (n.type === 'Identifier') return n.name;
  if (n.type === 'ThisExpression') return 'this';
  if (n.type === 'MemberExpression') {
    const o = dotted(n.object);
    if (!o) return null;
    const p = n.computed ? (n.property.type === 'Literal' ? String(n.property.value) : '[]') : n.property.name;
    return `${o}.${p}`;
  }
  return null;
}

function origin(n, T) {
  if (!n) return null;
  switch (n.type) {
    case 'Identifier': return T.get(n.name) || null;
    case 'MemberExpression': {
      const d = dotted(n);
      if (d && SOURCE.test(d)) return d.split('.').slice(0, 3).join('.');
      return origin(n.object, T);
    }
    case 'TemplateLiteral':
      for (const e of n.expressions) { const o = origin(e, T); if (o) return o; }
      return null;
    case 'BinaryExpression': return n.operator === '+' ? origin(n.left, T) || origin(n.right, T) : null;
    case 'LogicalExpression': return origin(n.left, T) || origin(n.right, T);
    case 'ConditionalExpression': return origin(n.consequent, T) || origin(n.alternate, T);
    case 'AwaitExpression': case 'UnaryExpression': case 'SpreadElement': return origin(n.argument, T);
    case 'ObjectExpression':
      for (const p of n.properties) { const o = origin(p.value || p.argument, T); if (o) return o; }
      return null;
    case 'ArrayExpression':
      for (const e of n.elements) { const o = origin(e, T); if (o) return o; }
      return null;
    case 'CallExpression': {
      const name = dotted(n.callee) || '';
      if (SANITIZER.test(name)) return null;
      if (PASSTHRU.test(name)) return origin(n.arguments[0], T);
      if (JOINERS.test(name)) for (const a of n.arguments) { const o = origin(a, T); if (o) return o; }
      if (n.callee.type === 'MemberExpression') return origin(n.callee.object, T);
      return null;
    }
    default: return null;
  }
}

function bind(pattern, o, T) {
  if (!pattern) return false;
  let added = false;
  const set = (name) => { if (!T.has(name)) { T.set(name, o); added = true; } };
  const go = (p) => {
    if (!p) return;
    if (p.type === 'Identifier') set(p.name);
    else if (p.type === 'ObjectPattern') p.properties.forEach((x) => go(x.value || x.argument));
    else if (p.type === 'ArrayPattern') p.elements.forEach(go);
    else if (p.type === 'AssignmentPattern') go(p.left);
    else if (p.type === 'RestElement') go(p.argument);
  };
  go(pattern);
  return added;
}

const hasSql = (n) => {
  let found = false;
  const visit = (x) => {
    if (!x || found) return;
    if (x.type === 'Literal' && typeof x.value === 'string' && SQLISH.test(x.value)) found = true;
    else if (x.type === 'TemplateLiteral') x.quasis.forEach((q) => { if (SQLISH.test(q.value.raw)) found = true; });
    else if (x.type === 'BinaryExpression') { visit(x.left); visit(x.right); }
  };
  visit(n);
  return found;
};
const hasHtml = (n) => {
  let found = false;
  const visit = (x) => {
    if (!x || found) return;
    if (x.type === 'Literal' && typeof x.value === 'string' && /</.test(x.value)) found = true;
    else if (x.type === 'TemplateLiteral') x.quasis.forEach((q) => { if (/</.test(q.value.raw)) found = true; });
    else if (x.type === 'BinaryExpression') { visit(x.left); visit(x.right); }
  };
  visit(n);
  return found;
};

export function taintFindings(code) {
  if (code.length > 600_000) return [];
  let ast;
  for (const sourceType of ['module', 'script']) {
    try {
      ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType, locations: true, allowHashBang: true, allowReturnOutsideFunction: true });
      break;
    } catch { /* coba tipe lain */ }
  }
  if (!ast) return [];

  const all = [];
  walk.full(ast, (n) => all.push(n));

  const T = new Map();
  for (let i = 0; i < 6; i++) {
    let changed = false;
    for (const n of all) {
      if (n.type === 'VariableDeclarator' && n.init) {
        const o = origin(n.init, T);
        if (o && bind(n.id, o, T)) changed = true;
      } else if (n.type === 'AssignmentExpression' && (n.operator === '=' || n.operator === '+=')) {
        if (n.left.type === 'MemberExpression' && !n.left.computed && SAFE_WRITE_PROP.test(n.left.property.name)) continue;
        const o = origin(n.right, T);
        if (!o) continue;
        let t = n.left;
        let nested = false;
        while (t.type === 'MemberExpression') { nested = true; t = t.object; }
        if (t.type === 'Identifier' && nested && SHARED_OBJECT.test(t.name)) continue; // tulis-properti ke objek bersama: jangan cemari identifier-nya
        if (t.type === 'Identifier' && bind(t, o, T)) changed = true;
      }
    }
    if (!changed) break;
  }

  const out = [];
  const seen = new Set();
  const report = (lvl, rule, o, sink, node) => {
    const line = node.loc.start.line;
    const key = `${rule}:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(F(lvl, rule, `Input pengguna (${o}) mengalir ke ${sink} (baris ${line})`));
  };

  for (const n of all) {
    if (n.type === 'CallExpression') {
      const c = n.callee;
      const obj = c.type === 'MemberExpression' ? dotted(c.object) || '' : '';
      const method = c.type === 'MemberExpression' && !c.computed ? c.property.name : c.type === 'Identifier' ? c.name : '';
      const a0 = n.arguments[0];
      const o0 = origin(a0, T);

      if (c.type === 'Identifier' && c.name === 'eval' && o0) report(2, 'taint-eval', o0, 'eval()', n);
      if (c.type === 'Identifier' && c.name === 'require' && o0) report(2, 'taint-eval', o0, 'require()', n);
      if (!o0) {
        // Pola yang butuh argumen selain yang pertama
        if (/^(?:setTimeout|setInterval)$/.test(method) && a0 && a0.type !== 'FunctionExpression' && a0.type !== 'ArrowFunctionExpression') {
          const o = origin(a0, T);
          if (o) report(2, 'taint-eval', o, `${method}() dengan string`, n);
        }
        continue;
      }
      if (method === 'execSync' || ((method === 'exec' || method === 'spawn' || method === 'spawnSync' || method === 'execFile') && (c.type === 'Identifier' || /child_?process|^cp$|^shell/i.test(obj))))
        report(2, 'taint-exec', o0, `${method}()`, n);
      if (/^(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|createReadStream|createWriteStream|unlink|unlinkSync|readdir|readdirSync|rm|rmSync)$/.test(method) && (c.type === 'Identifier' || /^(?:fs|fsp|fs\.promises)$/.test(obj)))
        report(2, 'taint-path', o0, `${method}()`, n);
      if (/^(?:sendFile|download)$/.test(method) && /^(?:res|response|reply)$/.test(obj)) report(2, 'taint-path', o0, `res.${method}()`, n);
      if (/^(?:query|execute|raw)$/.test(method) && c.type === 'MemberExpression' && (a0.type === 'TemplateLiteral' || a0.type === 'BinaryExpression' || /sql|query|stmt/i.test(a0.name || '')))
        report(2, 'taint-sqli', o0, `${method}()`, n);
      if (/^(?:get|all|run|exec)$/.test(method) && c.type === 'MemberExpression' && hasSql(a0) && !/child_?process|^cp$/i.test(obj)) report(2, 'taint-sqli', o0, `${method}()`, n);
      if (method === 'write' && /^document$/.test(obj)) report(2, 'taint-xss', o0, 'document.write()', n);
      if (/^(?:send|write|end)$/.test(method) && /^(?:res|response|reply)$/.test(obj)) report(hasHtml(a0) ? 2 : 1, 'taint-xss', o0, `res.${method}()`, n);
      if (method === 'redirect' && /^(?:res|response|reply)$/.test(obj)) report(1, 'taint-redirect', o0, 'res.redirect()', n);
      if (/^(?:assign|replace)$/.test(method) && /(?:^|\.)location$/.test(obj)) report(1, 'taint-redirect', o0, `location.${method}()`, n);
      if (/^(?:insertAdjacentHTML)$/.test(method)) report(2, 'taint-xss', o0, 'insertAdjacentHTML()', n);
    } else if (n.type === 'NewExpression' && n.callee.type === 'Identifier' && n.callee.name === 'Function') {
      for (const a of n.arguments) { const o = origin(a, T); if (o) { report(2, 'taint-eval', o, 'new Function()', n); break; } }
    } else if (n.type === 'AssignmentExpression' && n.left.type === 'MemberExpression') {
      const o = origin(n.right, T);
      if (!o) continue;
      const prop = !n.left.computed ? n.left.property.name : '';
      const d = dotted(n.left) || '';
      if (prop === 'innerHTML' || prop === 'outerHTML') report(2, 'taint-xss', o, prop, n);
      else if (/(?:^|\.)location(?:\.href)?$/.test(d)) report(1, 'taint-redirect', o, 'location', n);
    }
  }
  return out;
}
