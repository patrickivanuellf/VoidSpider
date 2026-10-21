import test from 'node:test';
import assert from 'node:assert/strict';
import { taintFindings } from '../lib/ast.js';
import { malwareFindings, binaryPayloadFindings } from '../lib/malware.js';
import { parseDeps, cvss3, lookup, toFindings, _test } from '../lib/deps.js';

const rules = (fs) => fs.map((f) => f.rule);

test('taint: input ke exec, eval, path, sqli, xss', () => {
  const code = `
const { exec } = require('child_process');
app.get('/a', (req, res) => {
  const name = req.query.name;
  const cmd = 'ls ' + name;
  exec(cmd);
  eval(req.body.code);
  fs.readFile(path.join('/data', req.params.file), () => {});
  db.query(\`SELECT * FROM t WHERE id=\${req.query.id}\`);
  res.send('<h1>' + name + '</h1>');
  res.redirect(req.query.next);
});`;
  const r = rules(taintFindings(code));
  for (const k of ['taint-exec', 'taint-eval', 'taint-path', 'taint-sqli', 'taint-xss', 'taint-redirect']) assert.ok(r.includes(k), k);
});

test('taint: sanitizer dan input aman tidak ditandai', () => {
  const code = `
app.get('/a', (req, res) => {
  const id = parseInt(req.query.id, 10);
  db.query('SELECT * FROM t WHERE id=' + id);
  const f = path.basename(req.params.file);
  fs.readFile(f, () => {});
  const re = /a/; re.exec(req.query.x);
  exec('ls -la');
});`;
  assert.deepEqual(rules(taintFindings(code)), []);
});

test('taint: kode yang tidak bisa di-parse tidak melempar error', () => {
  assert.deepEqual(taintFindings('const = = ;;'), []);
});

test('webshell PHP terdeteksi', () => {
  assert.ok(rules(malwareFindings('<?php @eval(base64_decode($_POST["x"])); ?>', 'php')).includes('webshell'));
  assert.ok(rules(malwareFindings('<?php system($_GET["cmd"]); ?>', 'php')).includes('webshell'));
  assert.ok(rules(malwareFindings('<?php $_POST["f"]($_POST["a"]); ?>', 'php')).includes('webshell'));
  assert.ok(rules(malwareFindings('GIF89a<?php echo 1; ?>', 'gif')).includes('webshell'));
  assert.ok(binaryPayloadFindings(Buffer.from([0xff, 0xd8, 0, 0, ...Buffer.from('<?php eval($_POST[1]);')]), 'jpg').length === 1);
});

test('PHP biasa tidak ditandai webshell', () => {
  const ok = '<?php echo htmlspecialchars($_GET["q"] ?? ""); $x = base64_encode("a"); ?>';
  assert.deepEqual(rules(malwareFindings(ok, 'php')), []);
});

test('JS: miner, packer, iframe tersembunyi, cloaking', () => {
  assert.ok(rules(malwareFindings('var m=new CoinHive.Anonymous("k");', 'js')).includes('miner'));
  assert.ok(rules(malwareFindings('eval(function(p,a,c,k,e,d){return p}("x",1,1,"".split("|"),0,{}))', 'js')).includes('obfuscation'));
  assert.ok(rules(malwareFindings('<iframe src="http://x" width="0" height="0"></iframe>', 'html')).includes('hidden-iframe'));
  assert.ok(rules(malwareFindings('if(document.referrer.indexOf("google")>0){window.location="http://spam"}', 'js')).includes('malware-redirect'));
});

test('parseDeps: npm v3, requirements, composer', () => {
  const lock = JSON.stringify({ packages: { '': { name: 'x' }, 'node_modules/lodash': { version: '4.17.15' }, 'node_modules/a/node_modules/b': { version: '1.0.0' } } });
  assert.deepEqual(parseDeps('package-lock.json', lock).map((d) => `${d.name}@${d.version}`).sort(), ['b@1.0.0', 'lodash@4.17.15']);
  const req = 'Django==3.0.1\nrequests>=2\n# komentar\nflask[async]==2.0.0 ; python_version>"3"';
  assert.deepEqual(parseDeps('requirements.txt', req).map((d) => d.name).sort(), ['django', 'flask']);
  const comp = JSON.stringify({ packages: [{ name: 'a/b', version: 'v1.2.3' }], 'packages-dev': [{ name: 'c/d', version: '2.0.0' }] });
  assert.equal(parseDeps('composer.lock', comp).length, 2);
});

test('cvss3: vektor kritis dan menengah', () => {
  assert.equal(cvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
});

test('lookup OSV dengan fetch palsu menghasilkan temuan berlevel', async () => {
  _test.cache.clear(); _test.details.clear();
  const calls = [];
  const fetchImpl = async (url, opt) => {
    calls.push(url);
    if (url.endsWith('/v1/querybatch')) {
      const q = JSON.parse(opt.body).queries;
      return { ok: true, json: async () => ({ results: q.map((x) => (x.package.name === 'lodash' ? { vulns: [{ id: 'GHSA-aaaa' }, { id: 'GHSA-bbbb' }] } : {})) }) };
    }
    const id = decodeURIComponent(url.split('/').pop());
    return { ok: true, json: async () => ({ id, summary: 's', database_specific: { severity: id === 'GHSA-aaaa' ? 'HIGH' : 'LOW' }, affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] }) };
  };
  const deps = [{ ecosystem: 'npm', name: 'lodash', version: '4.17.15' }, { ecosystem: 'npm', name: 'safe', version: '1.0.0' }];
  const f = toFindings(await lookup(deps, { fetchImpl }));
  assert.equal(f.length, 1);
  assert.equal(f[0].lvl, 2);
  assert.match(f[0].text, /lodash@4.17.15: 2 kerentanan/);
  assert.match(f[0].fix, /4\.17\.21/);
  await lookup(deps, { fetchImpl });
  assert.equal(calls.filter((u) => u.endsWith('querybatch')).length, 1, 'hasil kedua dari cache');
});

import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { auditFile, loadIgnore } from '../lib/filescan.js';

async function auditText(name, content) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'lb-'));
  const abs = path.join(dir, name);
  await fs.writeFile(abs, content);
  const st = await fs.lstat(abs);
  const r = await auditFile({ abs, rel: name, name, st, maxBytes: 2_000_000, isIgnored: await loadIgnore(dir) });
  await fs.rm(dir, { recursive: true });
  return r.findings;
}

test('filescan: IaC compose dan terraform', async () => {
  const c = await auditText('docker-compose.yml', 'services:\n  db:\n    image: mysql:latest\n    privileged: true\n    ports:\n      - "3306:3306"\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n');
  const r = rules(c);
  assert.ok(r.includes('iac-priv') && r.includes('iac-port') && r.includes('docker-latest'));
  const safe = await auditText('ok.yml', 'ports:\n  - "127.0.0.1:3306:3306"\n');
  assert.ok(!rules(safe).includes('iac-port'));
  const t = await auditText('main.tf', 'resource "aws_security_group_rule" "x" {\n from_port = 22\n cidr_blocks = ["0.0.0.0/0"]\n}\n');
  assert.ok(rules(t).includes('iac-open'));
});

test('filescan: webshell dan taint terdeteksi lewat auditFile', async () => {
  const w = await auditText('shell.php', '<?php eval(base64_decode($_POST["a"]));');
  assert.ok(w.some((f) => f.rule === 'webshell' && f.lvl === 2));
  const j = await auditText('srv.js', "const {exec}=require('child_process');app.get('/',(req,res)=>{exec('ping '+req.query.h)});");
  assert.ok(j.some((f) => f.rule === 'taint-exec'));
});

import { auditDns, baseDomain, spfFindings, dmarcFindings } from '../lib/dnsaudit.js';

test('baseDomain mengenali domain Indonesia dan IP', () => {
  assert.equal(baseDomain('www.situs.co.id'), 'situs.co.id');
  assert.equal(baseDomain('a.b.contoh.com'), 'contoh.com');
  assert.equal(baseDomain('127.0.0.1'), null);
  assert.equal(baseDomain('localhost'), null);
});

test('SPF dan DMARC: kasus lemah dan baik', () => {
  assert.equal(spfFindings([], true)[0].lvl, 1);
  assert.equal(spfFindings(['v=spf1 +all'], true)[0].lvl, 1);
  assert.deepEqual(spfFindings(['v=spf1 include:_spf.google.com -all'], true), []);
  assert.match(dmarcFindings(['v=DMARC1; p=none'], true)[0].text, /p=none/);
  assert.deepEqual(dmarcFindings(['v=DMARC1; p=reject; rua=mailto:a@b.c'], true), []);
});

test('auditDns dengan resolver palsu menemukan subdomain dangling', async () => {
  const nx = () => { const e = new Error('nx'); e.code = 'ENOTFOUND'; throw e; };
  const r = {
    resolveMx: async () => [{ exchange: 'mx.x', priority: 1 }],
    resolveTxt: async (n) => (n === 'contoh.com' ? [['v=spf1 -all']] : n === '_dmarc.contoh.com' ? [['v=DMARC1; p=reject; rua=mailto:a@b.c']] : nx()),
    resolveCaa: async () => [{ critical: 0, issue: 'letsencrypt.org' }],
    resolveCname: async (s) => (s === 'lama.contoh.com' ? ['hilang.example.net'] : nx()),
    resolve4: nx, resolve6: nx,
  };
  const fetchImpl = async (url) => {
    if (url.includes('crt.sh')) return { ok: true, json: async () => [{ name_value: 'contoh.com\nlama.contoh.com\n*.api.contoh.com' }] };
    if (url.includes('cloudflare-dns')) return { ok: true, json: async () => ({ Answer: [{ type: 43 }] }) };
    throw new Error('tidak diharapkan');
  };
  const res = await auditDns('www.contoh.com', { r, fetchImpl });
  assert.deepEqual(res.subdomains.sort(), ['api.contoh.com', 'lama.contoh.com']);
  assert.ok(res.findings.some((f) => f.rule === 'takeover' && /lama\.contoh\.com/.test(f.text)));
  assert.ok(!res.findings.some((f) => f.rule === 'spf' || f.rule === 'dmarc' || f.rule === 'caa' || f.rule === 'dnssec'));
});

import { execSync } from 'node:child_process';
import tlsMod from 'node:tls';
import { auditTls } from '../lib/tlsaudit.js';

test('auditTls: self-signed, TLS lama, dan nama tidak cocok', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'tls-'));
  execSync(`openssl req -x509 -newkey rsa:1024 -nodes -keyout ${dir}/k.pem -out ${dir}/c.pem -days 5 -subj "/CN=bukan-localhost.test" 2>/dev/null`);
  const server = tlsMod.createServer({
    key: await fs.readFile(`${dir}/k.pem`), cert: await fs.readFile(`${dir}/c.pem`),
    minVersion: 'TLSv1', maxVersion: 'TLSv1.2', ciphers: 'ALL:@SECLEVEL=0',
  }, (s) => s.end());
  await new Promise((res) => server.listen(0, '127.0.0.1', res));
  const port = server.address().port;
  const f = await auditTls('127.0.0.1', port);
  server.close();
  const r = f.map((x) => `${x.rule}:${x.text}`);
  assert.ok(f.some((x) => x.rule === 'tls-chain' && /self-signed/.test(x.text)), r.join('\n'));
  assert.ok(f.some((x) => x.rule === 'tls' && /14 hari/.test(x.text)), r.join('\n'));
  assert.ok(f.some((x) => x.rule === 'tls-chain' && /tidak cocok/.test(x.text)), r.join('\n'));
  assert.ok(f.some((x) => x.rule === 'tls-key' && /1024/.test(x.text)), r.join('\n'));
  assert.ok(f.some((x) => x.rule === 'tls-proto' && /TLS 1\.[01]/.test(x.text)), 'TLS lama harus terdeteksi: ' + r.join('\n'));
});

import { Baseline } from '../lib/drift.js';
import { makeNotifier } from '../lib/notify.js';
import { parseSshLine, parseCowrie, IntelAggregator } from '../lib/intel.js';
import { scanGitHistory, hasGit } from '../lib/githistory.js';
import { makeAgent, redact, snippet } from '../lib/agent.js';
import { toSarif } from '../lib/sarif.js';

test('drift: baseline pertama merekam, siklus berikutnya mendeteksi perubahan', async () => {
  const f = path.join(await fs.mkdtemp(path.join(os.tmpdir(), 'bl-')), 'b.json');
  const b1 = new Baseline(f);
  assert.deepEqual(b1.fileDrift('a.php', 'h1'), []);
  b1.fileDrift('b.txt', 'h2');
  b1.hostDrift(['cdn.sah.com']);
  b1.save();

  const b2 = new Baseline(f);
  assert.equal(b2.learning, false);
  assert.deepEqual(b2.fileDrift('b.txt', 'h2'), []);
  const changed = b2.fileDrift('a.php', 'BEDA');
  assert.equal(changed[0].rule, 'drift');
  assert.equal(changed[0].lvl, 1);
  assert.equal(b2.fileDrift('baru.php', 'x')[0].lvl, 1);
  assert.equal(b2.fileDrift('baru.txt', 'x')[0].lvl, 0);
  assert.equal(b2.hostDrift(['cdn.sah.com'])[0], undefined);
  assert.equal(b2.hostDrift(['evil.example'])[0].lvl, 2);
  b2.seenFiles.delete('b.txt');
  assert.match(b2.removed()[0].text, /1 berkas/);

  const b3 = new Baseline(f, { accept: true });
  b3.fileDrift('a.php', 'BEDA');
  b3.save();
  assert.deepEqual(new Baseline(f).fileDrift('a.php', 'BEDA'), []);
});

test('notify: siklus pertama ringkasan, berikutnya hanya yang baru, tanpa duplikat', async () => {
  const calls = [];
  const fetchImpl = async (url, o) => { calls.push({ url, body: JSON.parse(o.body) }); return { ok: true }; };
  const n = makeNotifier({ fetchImpl, env: { TELEGRAM_BOT_TOKEN: 'T0KEN', TELEGRAM_CHAT_ID: '42', TELEGRAM_API: 'http://x' }, label: 'situs' });
  const summ = { skor: 50, nilai: 'D', kritis: 1, sedang: 0, info: 0 };
  const item = { path: '/.env', f: { lvl: 2, rule: 'exposed', text: 'File .env terbuka' } };
  await n.cycle([item], summ);
  assert.equal(calls.length, 1);
  assert.match(calls[0].body.text, /Pemindaian pertama/);
  assert.equal(calls[0].url, 'http://x/botT0KEN/sendMessage');
  await n.cycle([item], summ);
  assert.equal(calls.length, 1, 'tidak diulang');
  await n.cycle([item, { path: '/x', f: { lvl: 2, rule: 'secret', text: 'Kunci AWS terlihat' } }, { path: '/y', f: { lvl: 0, rule: 'xcto', text: 'info' } }], summ);
  assert.equal(calls.length, 2);
  assert.match(calls[1].body.text, /Kunci AWS/);
  assert.doesNotMatch(calls[1].body.text, /info\b.*xcto/);
  const off = makeNotifier({ env: {} });
  assert.equal(off.enabled, false);
});

test('intel: parser SSH dan Cowrie, deteksi brute force dan sukses-setelah-gagal', () => {
  assert.deepEqual(parseSshLine('Oct 13 sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2'), { kind: 'ssh', action: 'fail', user: 'admin', ip: '203.0.113.9' });
  assert.equal(parseSshLine('Accepted publickey for root from 198.51.100.7 port 1 ssh2').action, 'ok');
  assert.equal(parseSshLine('hal lain'), null);
  assert.equal(parseCowrie(JSON.stringify({ eventid: 'cowrie.login.failed', src_ip: '203.0.113.9', username: 'root', password: 'rahasia' })).user, 'root');
  assert.ok(!JSON.stringify(parseCowrie(JSON.stringify({ eventid: 'cowrie.login.failed', src_ip: '203.0.113.9', username: 'root', password: 'rahasia' }))).includes('rahasia'));
  assert.match(parseCowrie(JSON.stringify({ eventid: 'cowrie.command.input', src_ip: '203.0.113.9', input: 'wget x\u0007' })).cmd, /wget x\?/);

  const ev = [];
  let t = 1_000_000;
  const agg = new IntelAggregator({ onEvent: (e) => ev.push(e), now: () => (t += 1000) });
  for (let i = 0; i < 6; i++) agg.ingest({ kind: 'ssh', action: 'fail', user: 'root', ip: '203.0.113.9' });
  assert.equal(ev.filter((e) => e.type === 'brute').length, 1, 'brute force dilaporkan sekali');
  agg.ingest({ kind: 'ssh', action: 'ok', user: 'root', ip: '203.0.113.9' });
  assert.ok(ev.some((e) => e.type === 'success-after-fails'));
  agg.ingest({ kind: 'ssh', action: 'fail', user: 'x', ip: 'bukan-ip' });
  assert.equal(agg.top()[0].ip, '203.0.113.9');
  assert.equal(agg.top().length, 1);
});

test('githistory: kunci yang sudah dihapus tetap ketemu di riwayat', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'git-'));
  const sh = (c) => execSync(c, { cwd: dir, stdio: 'ignore' });
  sh('git init -q && git config user.email a@b.c && git config user.name t');
  await fs.writeFile(path.join(dir, 'cfg.js'), 'const k = "AKIAABCDEFGHIJKLMNOP";\n');
  sh('git add . && git commit -q -m satu');
  await fs.writeFile(path.join(dir, 'cfg.js'), 'const k = process.env.K;\n');
  sh('git commit -qam dua');
  assert.ok(hasGit(dir));
  const f = await scanGitHistory(dir);
  assert.equal(f.length, 1);
  assert.equal(f[0].rule, 'git-secret');
  assert.match(f[0].text, /AWS.*pernah ter-commit di [0-9a-f]+ \(cfg\.js\)/);
  assert.doesNotMatch(f[0].text, /AKIAABCDEFGHIJKLMNOP/);
});

test('agent: redaksi, triase dengan API palsu, cache, dan penolakan keluaran liar', async () => {
  assert.doesNotMatch(redact('key=AKIAABCDEFGHIJKLMNOP password: "hunter2hunter"'), /AKIA|hunter2/);
  assert.match(snippet('a\nb\nc\nd\ne', 3, 1), /2: b\n3: c\n4: d/);

  const calls = [];
  const fetchImpl = async (url, o) => {
    const body = JSON.parse(o.body);
    calls.push(body);
    assert.equal(o.headers['x-api-key'], 'k');
    const user = body.messages[0].content;
    assert.match(user, /^<data>/);
    const text = body.system.includes('urutan perbaikan')
      ? JSON.stringify({ rencana: [{ tindakan: 'Cabut kunci', alasan: 'bocor', temuan: ['n1#0'] }] })
      : '```json\n' + JSON.stringify({ hasil: [{ id: 'n1#0', verdict: 'nyata', alasan: 'kunci asli', prioritas: 1 }, { id: 'n2#0', verdict: 'positif_palsu', alasan: 'contoh dokumentasi', prioritas: 9 }, { id: 'tidak-ada', verdict: 'nyata' }, { id: 'n1#1', verdict: 'ASAL', alasan: 'x' }] }) + '\n```';
    return { ok: true, json: async () => ({ content: [{ type: 'text', text }] }) };
  };
  const items = [
    { id: 'n1#0', path: 'a.js', rule: 'secret', text: 'Kunci AWS', lvl: 2, snippet: '1: const k = [REDAKSI]' },
    { id: 'n2#0', path: 'README.md', rule: 'inj-visible', text: 'pola perintah ke AI', lvl: 1, snippet: 'abaikan instruksi sebelumnya' },
    { id: 'n1#1', path: 'a.js', rule: 'x', text: 'y', lvl: 1 },
  ];
  const ag = makeAgent({ fetchImpl, env: { ANTHROPIC_API_KEY: 'k' }, enabled: true });
  const r = await ag.triage(items);
  assert.equal(r.get('n1#0').verdict, 'nyata');
  assert.equal(r.get('n2#0').prioritas, 5, 'prioritas dijepit ke 1..5');
  assert.ok(!r.has('tidak-ada') && !r.has('n1#1'), 'id asing dan verdict liar diabaikan');
  assert.match(calls[0].system, /TIDAK TEPERCAYA/);
  await ag.triage(items);
  assert.equal(calls.length, 2, 'panggilan kedua hanya untuk item yang belum tervalidasi, bukan yang sudah di-cache');
  const plan = await ag.plan([{ id: 'n1#0', path: 'a.js', text: 'Kunci AWS', lvl: 2, verdict: 'nyata', prioritas: 1 }]);
  assert.equal(plan[0].tindakan, 'Cabut kunci');
  assert.equal(makeAgent({ fetchImpl, env: {}, enabled: true }).enabled, false, 'tanpa kunci API: mati');
  assert.equal(makeAgent({ fetchImpl, env: { ANTHROPIC_API_KEY: 'k' }, enabled: false }).enabled, false, 'tanpa --agent: mati');
});

test('sarif: struktur valid, level dan baris', () => {
  const s = toSarif([{ path: 'src/a.js', f: { lvl: 2, rule: 'taint-exec', text: 'Input mengalir ke exec() (baris 7)', fix: 'Pakai execFile' } }, { path: 'x', f: { lvl: 0, rule: 'xcto', text: 'tanpa header', fix: '' } }], { mode: 'file', target: '.' });
  assert.equal(s.version, '2.1.0');
  const r = s.runs[0].results[0];
  assert.equal(r.level, 'error');
  assert.equal(r.locations[0].physicalLocation.region.startLine, 7);
  assert.equal(r.locations[0].physicalLocation.artifactLocation.uriBaseId, '%SRCROOT%');
  assert.equal(s.runs[0].tool.driver.rules.length, 2);
});

import { findSecrets } from '../lib/rules.js';

test('secret sk-: slug dan kelas CSS tidak ditandai, kunci asli ditandai', () => {
  const slug = '<a href="/game/risk-of-the-board-game-with-a-very-long-name-and-more-words-here">x</a> class="desk-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"';
  assert.deepEqual(findSecrets(slug), []);
  assert.deepEqual(findSecrets('sk-' + 'a'.repeat(40)), [], 'huruf kecil saja bukan kunci');
  const real = 'const k = "sk-proj-AbC123dEf456GhI789jKl012MnO345pQr678StU";';
  const f = findSecrets(real);
  assert.equal(f.length, 1);
  assert.match(f[0].text, /panjang \d+ karakter/);
  assert.doesNotMatch(f[0].text, /AbC123dEf456/, 'nilai tidak bocor ke teks temuan');
  assert.equal(findSecrets('const k = "sk-ant-api03-AbC123dEf456GhI789jKl012MnO345pQr678", ok', { file: true })[0].text.includes('baris 1'), true);
});

import { jwtScan, decodeJwtPart } from '../lib/jwt.js';
import { genericSecretFindings, _test as entTest } from '../lib/entropy.js';
import { detectWaf } from '../lib/waf.js';
import { loadUserProbes } from '../lib/userprobes.js';
import { bruteSubdomains } from '../lib/dnsaudit.js';

function makeJwt(header, payload) {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64(header)}.${b64(payload)}.fakesig${Date.now()}`;
}

test('jwt: alg:none, tanpa exp, klaim sensitif, dan token sah tidak ditandai', () => {
  assert.equal(decodeJwtPart('bukan-base64-valid!!'), null);
  const none = makeJwt({ alg: 'none', typ: 'JWT' }, { sub: '1' });
  const r1 = jwtScan(`token: "${none}"`);
  assert.ok(r1.some((f) => f.rule === 'jwt-none'));
  assert.ok(r1.some((f) => f.rule === 'jwt-noexp'));

  const sensitive = makeJwt({ alg: 'HS256' }, { sub: '1', exp: Math.floor(Date.now() / 1000) + 3600, password: 'x' });
  const r2 = jwtScan(sensitive);
  assert.ok(r2.some((f) => f.rule === 'jwt-claim'));
  assert.doesNotMatch(r2.map((f) => f.text).join(' '), /password":"x"|"x"/);

  const longExp = makeJwt({ alg: 'HS256' }, { exp: Math.floor(Date.now() / 1000) + 20 * 365 * 86400 });
  assert.ok(jwtScan(longExp).some((f) => f.rule === 'jwt-longexp'));

  const good = makeJwt({ alg: 'HS256' }, { sub: '1', exp: Math.floor(Date.now() / 1000) + 3600 });
  assert.deepEqual(jwtScan(good), []);
  assert.deepEqual(jwtScan('bukan.jwt sama sekali'), []);
});

test('entropy: kredensial acak terdeteksi, hash/uuid/angka tidak', () => {
  assert.ok(entTest.entropy('aaaaaaaaaa') < entTest.entropy('AbC123xYz9'));
  const real = 'const apiKey = "AbC123dEf456GhI789jKl012MnO345pQr";';
  const f1 = genericSecretFindings(real);
  assert.equal(f1.length, 1);
  assert.match(f1[0].text, /entropi \d/);
  assert.doesNotMatch(f1[0].text, /AbC123/);

  assert.deepEqual(genericSecretFindings('const token = "550e8400-e29b-41d4-a716-446655440000";'), [], 'uuid tidak ditandai');
  assert.deepEqual(genericSecretFindings('const commitSecret = "4b2f8b1c9e0a7d6f5c3b2a190887766554433221";'), [], 'hash hex tidak ditandai');
  assert.deepEqual(genericSecretFindings('const authToken = "1111111111111111111111111111";'), [], 'variasi karakter rendah tidak ditandai');
  assert.deepEqual(genericSecretFindings('const apiVersion = "v1"; const x = "AbC123dEf456";'), [], 'kata kunci harus persis, apiVersion bukan apiKey');
});

test('waf: fingerprint header dikenali, header biasa tidak', () => {
  assert.equal(detectWaf(new Headers({ 'cf-ray': '123-ABC' })), 'Cloudflare');
  assert.equal(detectWaf(new Headers({ 'x-sucuri-id': '1' })), 'Sucuri');
  assert.equal(detectWaf(new Headers({ server: 'nginx' })), null);
});

test('userprobes: memuat probe dari JSON, cocok dan tidak cocok', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'probes-'));
  await fs.writeFile(path.join(dir, 'a.json'), JSON.stringify([
    { path: '/debug', text: 'Halaman debug terbuka', lvl: 1, bodyMatch: 'Debug Console', ctMatch: 'text/html' },
  ]));
  const probes = loadUserProbes(dir);
  assert.equal(probes.length, 1);
  assert.equal(probes[0].ok({ body: '<h1>Debug Console</h1>', ct: 'text/html' }), true);
  assert.equal(probes[0].ok({ body: 'biasa saja', ct: 'text/html' }), false);
  assert.equal(loadUserProbes(path.join(dir, 'tidak-ada')).length, 0);
});

test('bruteSubdomains: hanya resolusi DNS, tidak menghubungi server target', async () => {
  const calls = [];
  const r = {
    resolve4: async (h) => { calls.push(h); if (h === 'api.x.test') return ['1.2.3.4']; throw Object.assign(new Error('nx'), { code: 'ENOTFOUND' }); },
    resolve6: async () => { throw Object.assign(new Error('nx'), { code: 'ENOTFOUND' }); },
    resolveCname: async () => { throw Object.assign(new Error('nx'), { code: 'ENOTFOUND' }); },
  };
  const found = await bruteSubdomains('x.test', r);
  assert.deepEqual(found, ['api.x.test']);
  assert.ok(calls.length > 1);
});

import { zapVersion, zapSpider, zapActiveScan, zapAlerts, alertsToFindings } from '../lib/zap.js';

function mockZap({ spiderSteps = [100], ascanSteps = [100], pscanQueue = [0], alerts = [] } = {}) {
  const calls = [];
  let spiderIdx = 0, ascanIdx = 0, pscanIdx = 0;
  const fetchImpl = async (u) => {
    calls.push(u);
    const p = new URL(u);
    const path = p.pathname;
    const ok = (json) => ({ ok: true, json: async () => json });
    if (path === '/JSON/core/view/version/') return ok({ version: '2.15.0' });
    if (path === '/JSON/spider/action/scan/') return ok({ scan: '0' });
    if (path === '/JSON/spider/view/status/') return ok({ status: String(spiderSteps[Math.min(spiderIdx++, spiderSteps.length - 1)]) });
    if (path === '/JSON/pscan/view/recordsToScan/') return ok({ recordsToScan: String(pscanQueue[Math.min(pscanIdx++, pscanQueue.length - 1)]) });
    if (path === '/JSON/ascan/action/scan/') return ok({ scan: '1' });
    if (path === '/JSON/ascan/view/status/') return ok({ status: String(ascanSteps[Math.min(ascanIdx++, ascanSteps.length - 1)]) });
    if (path === '/JSON/core/view/alerts/') return ok({ alerts });
    return { ok: false, status: 404 };
  };
  return { fetchImpl, calls };
}

test('zap: version, spider menunggu sampai 100% dan antrean pasif kosong', async () => {
  const { fetchImpl, calls } = mockZap({ spiderSteps: [0, 40, 100], pscanQueue: [5, 0] });
  assert.equal(await zapVersion('http://127.0.0.1:8080', 'KEY', fetchImpl), '2.15.0');
  await zapSpider('http://127.0.0.1:8080', 'https://situsmu.com', 'KEY', fetchImpl, { delay: 1 });
  assert.ok(calls.every((u) => u.includes('apikey=KEY')), 'semua panggilan menyertakan apiKey');
  assert.ok(calls.some((u) => u.includes('/JSON/pscan/view/recordsToScan/')));
});

test('zap: active scan menunggu sampai selesai', async () => {
  const { fetchImpl } = mockZap({ ascanSteps: [10, 60, 100] });
  await zapActiveScan('http://127.0.0.1:8080', 'https://situsmu.com', 'KEY', fetchImpl, { delay: 1 });
});

test('zap: timeout polling melempar error, bukan diam-diam dianggap selesai', async () => {
  const { fetchImpl } = mockZap({ spiderSteps: [0, 0, 0] });
  await assert.rejects(() => zapSpider('http://127.0.0.1:8080', 'x', 'KEY', fetchImpl, { max: 2, delay: 1 }));
});

test('zap: alert dikelompokkan, risk dipetakan, confidence Low menurunkan tingkat', async () => {
  const alerts = [
    { alert: 'SQL Injection', risk: 'High', confidence: 'High', url: 'https://x/a?id=1', param: 'id', solution: '<p>Pakai parameterized query.</p>' },
    { alert: 'SQL Injection', risk: 'High', confidence: 'High', url: 'https://x/b?id=2', param: 'id' },
    { alert: 'X-Content-Type-Options Header Missing', risk: 'Low', confidence: 'Low', url: 'https://x/a' },
    { alert: 'X-Content-Type-Options Header Missing', risk: 'Low', confidence: 'Low', url: 'https://x/b' },
    { alert: 'X-Content-Type-Options Header Missing', risk: 'Low', confidence: 'Low', url: 'https://x/c' },
  ];
  const f = alertsToFindings(alerts);
  const sqli = f.find((x) => x.text.includes('SQL Injection'));
  assert.equal(sqli.lvl, 2);
  assert.match(sqli.text, /id=1.*id=2|id=2.*id=1/);
  assert.match(sqli.fix, /parameterized query/);
  assert.doesNotMatch(sqli.fix, /<p>/);
  const xcto = f.find((x) => x.text.includes('X-Content-Type-Options'));
  assert.equal(xcto.lvl, 0, 'risk Low + confidence Low tetap lvl 0, tidak minus');
});

test('zap: pengelompokan membatasi jumlah URL contoh per alert', async () => {
  const alerts = Array.from({ length: 10 }, (_, i) => ({ alert: 'Missing Header', risk: 'Low', confidence: 'Medium', url: `https://x/${i}` }));
  const f = alertsToFindings(alerts, { maxPerGroup: 3 });
  assert.equal(f.length, 1);
  assert.match(f[0].text, /\+7 URL lain/);
});
