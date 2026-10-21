/* Aturan deteksi bersama untuk mode web dan mode berkas.
   Semua pemeriksaan pasif: hanya membaca, tidak ada percobaan eksploitasi. */

/* ---------- Saran perbaikan per aturan ---------- */

export const FIX = {
  csp: 'Tambahkan header Content-Security-Policy, mulai dari default-src \'self\' lalu longgarkan seperlunya.',
  'csp-weak': 'Hapus \'unsafe-inline\', \'unsafe-eval\', dan wildcard (*) dari CSP. Pakai nonce atau hash untuk skrip inline.',
  xfo: 'Kirim X-Frame-Options: DENY atau CSP frame-ancestors \'none\' supaya halaman tidak bisa dibingkai.',
  xcto: 'Kirim X-Content-Type-Options: nosniff.',
  refpol: 'Kirim Referrer-Policy: strict-origin-when-cross-origin (atau lebih ketat).',
  permpol: 'Kirim Permissions-Policy untuk mematikan fitur browser yang tidak dipakai (kamera, mikrofon, geolokasi).',
  hsts: 'Kirim Strict-Transport-Security: max-age=31536000; includeSubDomains setelah seluruh situs siap HTTPS.',
  'hsts-weak': 'Naikkan max-age HSTS minimal 15552000 (180 hari), idealnya 31536000.',
  xpb: 'Matikan header X-Powered-By di server atau framework (mis. app.disable(\'x-powered-by\'), expose_php=Off).',
  serverver: 'Sembunyikan versi di header Server (server_tokens off di Nginx, ServerTokens Prod di Apache).',
  generator: 'Hapus meta generator yang membuka versi CMS, dan perbarui CMS ke versi terbaru.',
  cors: 'Ganti Access-Control-Allow-Origin: * dengan daftar origin yang memang perlu.',
  'cookie-secure': 'Tambahkan atribut Secure pada cookie.',
  'cookie-httponly': 'Tambahkan atribut HttpOnly pada cookie sesi supaya tidak terbaca JavaScript.',
  'cookie-samesite': 'Tambahkan SameSite=Lax (atau Strict) pada cookie.',
  'cookie-none': 'SameSite=None wajib dipasangkan dengan Secure. Pakai Lax kalau lintas situs tidak diperlukan.',
  mixed: 'Ubah semua sumber http:// menjadi https:// atau path relatif.',
  sri: 'Tambahkan atribut integrity dan crossorigin pada skrip/stylesheet pihak ketiga, atau host sendiri file-nya.',
  csrf: 'Tambahkan token CSRF pada form sensitif dan atur cookie SameSite.',
  formhttp: 'Arahkan action form ke https://.',
  pwhttp: 'Layani halaman login lewat HTTPS saja.',
  pwget: 'Form berisi sandi harus memakai method="post", karena method GET menaruh sandi di URL dan log server.',
  'pw-cache': 'Kirim Cache-Control: no-store pada halaman yang berisi form sandi.',
  'inj-hidden': 'Periksa dan hapus teks tersembunyi yang berisi perintah ke AI. Konten seperti ini bisa membajak asisten AI yang membaca halaman.',
  'inj-visible': 'Periksa konteksnya. Kalau itu bukan contoh/dokumentasi, hapus kalimat yang memerintah AI.',
  exposed: 'Hapus file dari folder publik dan tolak aksesnya di web server. Anggap semua isinya sudah bocor: ganti password dan kunci yang ada di dalamnya.',
  secret: 'Cabut (revoke) kunci itu sekarang, buat yang baru, simpan di environment variable atau secret manager, dan bersihkan riwayat Git bila sudah pernah di-commit.',
  '5xx': 'Cek log server untuk penyebab error.',
  '4xx': 'Perbaiki atau hapus tautan yang putus.',
  slow: 'Periksa performa server, caching, dan ukuran respons.',
  tls: 'Perbarui sertifikat TLS (aktifkan perpanjangan otomatis, mis. certbot).',
  nohttps: 'Pasang redirect permanen (301) dari http ke https.',
  dirlist: 'Matikan directory listing (autoindex off di Nginx, Options -Indexes di Apache).',
  errleak: 'Matikan mode debug dan tampilkan halaman error generik. Catat detail error hanya di log server.',
  sourcemap: 'Jangan sajikan file .map di produksi kecuali memang perlu.',
  'internal-ip': 'Hapus alamat IP internal dari konten publik.',
  securitytxt: 'Buat /.well-known/security.txt berisi Contact: agar peneliti tahu ke mana melapor.',
  'file-sensitive': 'Jangan simpan file ini di folder yang dipublikasikan atau di-commit. Masukkan ke .gitignore.',
  'file-git': 'Jangan ikutkan folder VCS (.git, .svn) saat deploy. Kalau terlanjur publik, anggap seluruh kode dan riwayatnya sudah bocor.',
  'file-exec': 'Pastikan berkas eksekusi ini memang sah dan berasal dari sumber tepercaya. Jangan simpan biner di folder web.',
  'file-doubleext': 'Ekstensi ganda adalah trik penyamaran malware. Periksa dan hapus berkas ini kalau tidak dikenal.',
  'file-masquerade': 'Isi berkas ini biner eksekusi padahal ekstensinya dokumen/gambar. Perlakukan sebagai mencurigakan.',
  'file-perm': 'Perketat izin berkas (chmod 600 untuk rahasia, 644 untuk berkas biasa, jangan world-writable).',
  'code-eval': 'Hindari eval()/new Function(). Pakai parser atau pemetaan aman untuk data dinamis.',
  'code-exec': 'Jangan membangun perintah shell dari input. Pakai execFile/subprocess dengan argumen terpisah tanpa shell.',
  'code-xss': 'Pakai textContent atau sanitasi (mis. DOMPurify) sebelum menyisipkan HTML.',
  'code-sqli': 'Pakai parameterized query / prepared statement, jangan menyambung string SQL.',
  'code-tls': 'Jangan mematikan verifikasi sertifikat TLS. Pasang CA yang benar sebagai gantinya.',
  'code-hash': 'MD5/SHA-1 tidak aman untuk keamanan. Untuk sandi pakai argon2/bcrypt/scrypt, untuk integritas pakai SHA-256.',
  'code-deser': 'Jangan deserialisasi data tidak tepercaya (pickle, unserialize, yaml.load tanpa SafeLoader).',
  'code-lfi': 'Jangan meng-include file dari input pengguna. Pakai daftar putih path.',
  'code-shell': 'Jangan jalankan skrip hasil unduhan langsung lewat pipe ke shell. Unduh, periksa, baru jalankan.',
  'code-perm': 'Hindari chmod 777. Beri izin sekecil mungkin.',
  'code-debug': 'Matikan mode debug di produksi.',
  'trojan-source': 'Karakter kontrol bidi bisa membuat kode tampak berbeda dari yang dijalankan (Trojan Source). Hapus kecuali sah.',
  zerowidth: 'Karakter tak terlihat di kode/teks bisa menyembunyikan perintah. Periksa dan hapus.',
  'pkg-script': 'Tinjau skrip install di package.json. Skrip seperti ini jalan otomatis saat npm install.',
  'pkg-pin': 'Hindari versi "*", "latest", URL atau git mentah. Kunci versi dan commit lockfile.',
  'pkg-nolock': 'Commit lockfile (package-lock.json) supaya dependensi bisa direproduksi dan diaudit.',
  'docker-root': 'Tambahkan instruksi USER non-root di Dockerfile.',
  'docker-latest': 'Pakai tag versi tetap (atau digest) untuk base image, jangan :latest.',
  'jwt-none': 'Token dengan alg:none tidak punya tanda tangan sama sekali. Pastikan server menolak alg:none saat verifikasi.',
  'jwt-noexp': 'Tambahkan klaim exp supaya token kedaluwarsa dan tidak berlaku selamanya kalau bocor.',
  'jwt-longexp': 'Pertimbangkan masa berlaku yang lebih pendek, dan pakai refresh token untuk sesi panjang.',
  'jwt-claim': 'Jangan taruh data sensitif di payload JWT. Payload hanya di-encode base64, bukan dienkripsi, dan siapa pun bisa membacanya.',
  'secret-generic': 'Ini hasil deteksi heuristik (bukan format kunci yang dikenal): periksa manual isinya sebelum mencabut atau mengganti apa pun.',
  blocked: 'Longgarkan aturan WAF/rate-limit untuk IP pemindaimu, atau anggap hasil audit ini tidak lengkap.',
  zap: 'Lihat solusi dari ZAP pada temuan ini; validasi manual sebelum memperbaiki, DAST bisa salah mengira.',
  cve: 'Perbarui paket ke versi yang sudah diperbaiki, lalu jalankan ulang audit.',
  'cve-skip': 'Pemeriksaan CVE memakai api.osv.dev (hanya nama paket dan versi yang dikirim). Pastikan ada koneksi internet.',
  spf: 'Buat satu record SPF yang berakhir dengan -all (atau ~all), mis. "v=spf1 include:_spf.google.com -all".',
  dmarc: 'Buat record TXT _dmarc dengan p=quarantine atau p=reject, dan tambahkan rua=mailto:alamat-laporan.',
  dkim: 'Aktifkan DKIM di penyedia email, lalu publikasikan record TXT selector._domainkey.',
  caa: 'Tambahkan record CAA supaya hanya CA yang kamu pilih yang boleh menerbitkan sertifikat.',
  dnssec: 'Aktifkan DNSSEC di registrar dan penyedia DNS.',
  takeover: 'Hapus record DNS yang menunjuk ke layanan yang sudah tidak dipakai, atau klaim kembali layanannya, sebelum orang lain mengambilnya.',
  'tls-proto': 'Matikan TLS 1.0 dan 1.1 di server (ssl_protocols TLSv1.2 TLSv1.3; di Nginx).',
  'tls-cipher': 'Matikan cipher lemah (3DES, RC4, NULL, EXPORT). Pakai profil cipher modern (Mozilla SSL Configuration Generator).',
  'tls-chain': 'Pasang sertifikat yang valid dan rantai lengkap (fullchain.pem), dengan nama host yang cocok.',
  'tls-key': 'Terbitkan ulang sertifikat dengan kunci RSA minimal 2048 bit atau ECDSA.',
  webshell: 'Isolasi berkas ini, bandingkan dengan sumber asli, periksa log akses untuk siapa yang mengunggahnya, lalu ganti semua kredensial server dan CMS.',
  obfuscation: 'Kode yang diacak jarang punya alasan sah. Bandingkan dengan sumber asli atau paket resmi, dan hapus kalau tidak dikenal.',
  miner: 'Hapus skrip penambang kripto itu dan cari tahu bagaimana skrip itu bisa masuk.',
  'hidden-iframe': 'Iframe tersembunyi sering dipakai untuk menyuntikkan konten berbahaya. Periksa dan hapus kalau bukan buatanmu.',
  'malware-redirect': 'Pengalihan khusus untuk pengunjung dari mesin pencari adalah tanda situs diretas (cloaking). Bersihkan berkas dan ganti kredensial.',
  'reverse-shell': 'Pola reverse shell memberi penyerang akses ke server. Isolasi, selidiki, dan anggap server terkompromi.',
  'open-redirect': 'Validasi parameter redirect dengan daftar putih domain internal. Jangan langsung memakai input pengguna sebagai Location.',
  'auth-hint': 'Samakan pesan error login (jangan bedakan user ada/tidak). Aktifkan rate limit dan CAPTCHA setelah beberapa gagal.',
  'cors-cred': 'Jangan gabungkan Access-Control-Allow-Origin: * dengan Access-Control-Allow-Credentials: true.',
  'safe-xss-reflect': 'Encode output sesuai konteks dan pasang CSP. Ini sinyal pantulan, verifikasi manual di staging.',
  'safe-sql-error': 'Gunakan prepared statement. Sinyal error SQL — bukan bukti eksploitasi penuh.',
  stack: 'Fingerprint teknologi membantu penyerang. Sembunyikan versi di header dan meta generator.',
  'stack-wp': 'Nonaktifkan enumerasi author (plugin security atau nonaktifkan arsip author).',
  'stack-laravel': 'Matikan APP_DEBUG di produksi dan jangan tampilkan Whoops ke publik.',
  'param-suspect': 'Jangan teruskan input path mentah ke filesystem. Validasi dan batasi direktori.',
  'form-external': 'Pastikan form ke domain luar memang disengaja (payment gateway dll) dan memakai HTTPS.',
  drift: 'Pastikan perubahan ini memang kamu lakukan. Kalau tidak, anggap sebagai tanda peretasan. Kalau sah, jalankan ulang dengan --terima-perubahan.',
  'taint-exec': 'Input pengguna mengalir ke eksekusi perintah. Validasi dengan daftar putih dan pakai execFile dengan argumen terpisah.',
  'taint-eval': 'Input pengguna mengalir ke eval/Function. Hapus penggunaannya atau ganti dengan parser data.',
  'taint-sqli': 'Input pengguna mengalir ke query SQL. Pakai parameterized query.',
  'taint-path': 'Input pengguna dipakai sebagai path berkas. Normalisasi dan batasi ke folder tertentu (path traversal).',
  'taint-xss': 'Input pengguna dikirim ke HTML tanpa escape. Escape output atau pakai textContent.',
  'taint-redirect': 'Input pengguna dipakai sebagai tujuan redirect. Validasi dengan daftar putih domain (open redirect).',
  'iac-open': 'Batasi akses jaringan ke rentang yang dibutuhkan saja, jangan 0.0.0.0/0.',
  'iac-priv': 'Jangan jalankan container dengan hak berlebih. Hapus privileged, hostNetwork, dan mount docker.sock.',
  'iac-port': 'Ikat port database ke 127.0.0.1 (mis. "127.0.0.1:3306:3306") atau jangan dipublikasikan sama sekali.',
  'iac-public': 'Jangan membuat resource publik (bucket/database) kecuali memang dimaksudkan.',
  'git-secret': 'Cabut kunci itu, buat yang baru, lalu bersihkan riwayat dengan git filter-repo atau BFG. Mencabut kunci adalah langkah yang wajib, karena riwayat bisa sudah tersalin.',
  'ssh-brute': 'Pakai login kunci SSH saja, matikan password, pasang fail2ban, dan pertimbangkan mengubah atau membatasi port SSH.',
  unreachable: 'Periksa apakah target ada dan tidak memblokir pemindai (untuk situs) atau izin bacanya benar (untuk berkas).',
};

/* ---------- Temuan dan skor ---------- */

export const F = (lvl, rule, text, fix) => ({ lvl, rule, text, fix: fix ?? FIX[rule] ?? '' });
export const fkey = (f) => `${f.rule}|${f.text}`;

const WEIGHT = [1, 3, 10];

/** Skor 0-100 dari temuan unik. Makin banyak temuan, makin turun, dengan penurunan yang melandai. */
export function score(findings) {
  const seen = new Set();
  let penalty = 0;
  for (const f of findings) {
    const k = fkey(f);
    if (seen.has(k)) continue;
    seen.add(k);
    penalty += WEIGHT[f.lvl] || 0;
  }
  const s = Math.round(100 * Math.exp(-penalty / 45));
  const grade = s >= 90 ? 'A' : s >= 75 ? 'B' : s >= 60 ? 'C' : s >= 40 ? 'D' : 'F';
  return { score: s, grade };
}

/* ---------- Pola umum ---------- */

export const INJ =
  /(ignore|disregard|forget|override)\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules)|abaikan\s+(semua\s+)?(instruksi|perintah)(\s+sebelumnya)?|(reveal|show|print|tampilkan)\s+(the\s+|your\s+)?system\s*prompt|you\s+are\s+now\s+(in\s+)?(dan|developer\s+mode)/i;

// Karakter tak terlihat: tag Unicode (dipakai untuk menyelundupkan prompt), bidi (Trojan Source), zero-width.
export const INVISIBLE_TAG = /[\u{E0000}-\u{E007F}]/u;
export const BIDI = /[\u202A-\u202E\u2066-\u2069]/;
export const ZEROWIDTH = /[\u200B-\u200D\u2060\uFEFF]/g;

// Kunci asli tampak acak: ada huruf besar, huruf kecil, dan angka. Slug seperti "risk-board-game-..." tidak lolos.
const looksRandom = (m) => /\d/.test(m) && /[a-z]/.test(m) && /[A-Z]/.test(m);

// Menolak placeholder jelas (<ISI_DI_SINI>, xxxx, changeme, your-secret, ***) supaya aturan
// "kredensial tertulis langsung di kode" tidak menandai contoh/template sebagai temuan nyata.
function notPlaceholder(full) {
  const v = (/[:=]\s*['"]([^'"]+)['"]/.exec(full) || [, full])[1];
  if (/^(.)\1*$/.test(v)) return false; // satu karakter diulang (xxxx, ****, 0000)
  if (/^<.*>$/.test(v)) return false; // <ISI_DENGAN_SECRET_ANDA>
  if (/change.?me|your[_-]?(?:secret|key|token|password)|example|placeholder|dummy|contoh/i.test(v)) return false;
  return true;
}

// [pola, nama, level, hanyaBerkas, validator?]
export const SECRETS = [
  [/AKIA[0-9A-Z]{16}/, 'Kunci akses AWS', 2],
  [/ghp_[A-Za-z0-9]{36}/, 'Token GitHub', 2],
  [/github_pat_[A-Za-z0-9_]{50,}/, 'Token GitHub (fine-grained)', 2],
  [/sk_live_[A-Za-z0-9]{20,}/, 'Kunci Stripe live', 2],
  [/-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/, 'Private key', 2],
  [/(?<![A-Za-z0-9_-])sk-(?:proj-|ant-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}(?![A-Za-z0-9_-])/, 'Kunci API bergaya sk-', 2, false, looksRandom],
  [/xox[baprs]-[0-9A-Za-z-]{10,}/, 'Token Slack', 2],
  [/SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/, 'Kunci SendGrid', 2],
  [/npm_[A-Za-z0-9]{36}/, 'Token npm', 2],
  [/(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis):\/\/[^\s:@/'"]+:[^\s@/'"]{3,}@/i, 'Connection string database berisi sandi', 2],
  [/AIza[0-9A-Za-z_-]{35}/, 'Kunci API Google (pastikan dibatasi per domain)', 1],
  [/eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, 'JWT terlihat (lihat pemeriksaan JWT terpisah untuk risiko sebenarnya)', 0],
  [/(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*['"][^'"\s]{8,}['"]/i, 'Kredensial tertulis langsung di kode', 1, true, notPlaceholder],
  [/SB-Mid-server-[A-Za-z0-9_-]+/, 'Kunci Midtrans server', 2],
  [/SB-Mid-client-[A-Za-z0-9_-]+/, 'Kunci Midtrans client', 1],
  [/xnd_production_[A-Za-z0-9]+/, 'Kunci Xendit production', 2],
  [/xnd_development_[A-Za-z0-9]+/, 'Kunci Xendit development', 1],
  [/(?:^|[\s"'=])xox[baprs]-[A-Za-z0-9-]{10,}/, 'Token Slack', 2],
  [/https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/, 'Webhook Discord', 1],
  [/(?:bot)?[0-9]{8,10}:[A-Za-z0-9_-]{35}/, 'Token bot Telegram (pola)', 1],
  [/sk_test_[A-Za-z0-9]{20,}/, 'Kunci Stripe test', 0],
  [/SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/, 'Kunci SendGrid', 2],
];


/** Kecocokan pertama yang lolos validator, atau null. */
export function secretMatch([re, , , , ok], text) {
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
  let m;
  while ((m = g.exec(text))) {
    if (!ok || ok(m[0])) return m;
    if (m[0].length === 0) g.lastIndex++;
  }
  return null;
}

/** Cari rahasia. Nilainya TIDAK PERNAH dikembalikan: hanya jenis, panjang, dan konteks sebelum nilai (mode situs) atau nomor baris (mode berkas). */
export function findSecrets(text, { file = false } = {}) {
  const out = [];
  if (!text) return out;
  for (const entry of SECRETS) {
    const [, name, lvl, fileOnly] = entry;
    if (fileOnly && !file) continue;
    const m = secretMatch(entry, text);
    if (!m) continue;
    if (file) {
      const line = text.slice(0, m.index).split('\n').length;
      out.push(F(lvl, 'secret', `${name} terdeteksi (baris ${line})`));
    } else {
      const before = text.slice(Math.max(0, m.index - 14), m.index).replace(/[\s\u0000-\u001f]+/g, ' ');
      out.push(F(lvl, 'secret', `${name} terlihat di sumber (konteks sebelum: "${before}", panjang ${m[0].length} karakter)`));
    }
  }
  return out;
}

/* ---------- Probe file sensitif (mode web, GET saja) ---------- */

const envOk = (r) => /^[A-Z][A-Z0-9_]*\s*=/m.test(r.body) && !/<html/i.test(r.body);
const sqlOk = (r) => /CREATE TABLE|INSERT INTO/i.test(r.body);
const archOk = (r) => /zip|gzip|x-tar|octet-stream/i.test(r.ct) && !/html|text\/plain/i.test(r.ct);
const jsonHas = (re) => (r) => /json/i.test(r.ct) && re.test(r.body);

export const PROBES = [
  { p: '/.env', t: 'File .env dapat diakses publik', ok: envOk },
  { p: '/.env.local', t: 'File .env.local dapat diakses publik', ok: envOk },
  { p: '/.env.production', t: 'File .env.production dapat diakses publik', ok: envOk },
  { p: '/.env.backup', t: 'Cadangan .env dapat diakses publik', ok: envOk },
  { p: '/.git/config', t: 'Repositori .git terbuka ke publik', ok: (r) => /\[core\]/.test(r.body) },
  { p: '/.git/HEAD', t: 'Repositori .git terbuka ke publik', ok: (r) => /^ref:\s/.test(r.body) },
  { p: '/.svn/entries', t: 'Repositori .svn terbuka ke publik', ok: (r) => /^\d+\s*\n\s*dir/m.test(r.body) },
  { p: '/.aws/credentials', t: 'Kredensial AWS terbuka ke publik', ok: (r) => /aws_access_key_id/i.test(r.body) },
  { p: '/id_rsa', t: 'Private key SSH terbuka ke publik', ok: (r) => /BEGIN [A-Z ]*PRIVATE KEY/.test(r.body) },
  { p: '/backup.zip', t: 'Arsip backup terbuka ke publik', ok: archOk },
  { p: '/backup.tar.gz', t: 'Arsip backup terbuka ke publik', ok: archOk },
  { p: '/site.zip', t: 'Arsip situs terbuka ke publik', ok: archOk },
  { p: '/backup.sql', t: 'Dump database terbuka ke publik', ok: sqlOk },
  { p: '/db.sql', t: 'Dump database terbuka ke publik', ok: sqlOk },
  { p: '/dump.sql', t: 'Dump database terbuka ke publik', ok: sqlOk },
  { p: '/database.sql', t: 'Dump database terbuka ke publik', ok: sqlOk },
  { p: '/phpinfo.php', t: 'phpinfo() terbuka ke publik', ok: (r) => /PHP Version/.test(r.body) },
  { p: '/wp-config.php.bak', t: 'Cadangan wp-config terbuka ke publik', ok: (r) => /DB_PASSWORD/.test(r.body) },
  { p: '/config.php.bak', t: 'Cadangan config.php terbuka ke publik', ok: (r) => /<\?php/.test(r.body) },
  { p: '/.htpasswd', t: 'File .htpasswd terbuka ke publik', ok: (r) => /^[^:\s<]+:\S+/m.test(r.body) && !/<html/i.test(r.body) },
  { p: '/server-status', t: 'Halaman server-status terbuka ke publik', ok: (r) => /Apache Server Status/i.test(r.body) },
  { p: '/actuator/env', t: 'Spring Actuator /env terbuka ke publik', ok: jsonHas(/propertySources/) },
  { p: '/phpmyadmin/', t: 'phpMyAdmin terbuka ke publik', lvl: 1, ok: (r) => /phpMyAdmin/i.test(r.body) },
  { p: '/wp-json/wp/v2/users', t: 'Daftar pengguna WordPress terbuka lewat REST API', lvl: 1, ok: jsonHas(/"slug"/) },
  { p: '/xmlrpc.php', t: 'xmlrpc.php aktif (sering dipakai untuk brute force)', lvl: 0, ok: (r) => /XML-RPC server accepts POST requests only/i.test(r.body) },
  { p: '/swagger.json', t: 'Dokumentasi API (swagger) terbuka ke publik', lvl: 0, ok: jsonHas(/"swagger"|"openapi"/) },
  { p: '/openapi.json', t: 'Dokumentasi API (openapi) terbuka ke publik', lvl: 0, ok: jsonHas(/"openapi"/) },
  { p: '/package.json', t: 'package.json terbuka ke publik (membuka daftar dependensi)', lvl: 0, ok: jsonHas(/"(?:dependencies|devDependencies|scripts)"/) },
  { p: '/composer.lock', t: 'composer.lock terbuka ke publik (membuka daftar dependensi)', lvl: 0, ok: jsonHas(/"packages"/) },
  { p: '/.DS_Store', t: 'File .DS_Store terbuka ke publik', lvl: 0, ok: (r) => r.body.includes('Bud1') },
  // --- tambahan v9.2: probe yang sering muncul di infrastruktur Indonesia ---
  { p: '/adminer.php', t: 'Adminer terbuka ke publik', lvl: 2, ok: (r) => /Adminer|Login/i.test(r.body) && /server|username|password/i.test(r.body) },
  { p: '/adminer/', t: 'Adminer terbuka ke publik', lvl: 2, ok: (r) => /Adminer/i.test(r.body) },
  { p: '/phpmyadmin/index.php', t: 'phpMyAdmin terbuka ke publik', lvl: 1, ok: (r) => /phpMyAdmin/i.test(r.body) },
  { p: '/pma/', t: 'phpMyAdmin (alias) terbuka ke publik', lvl: 1, ok: (r) => /phpMyAdmin/i.test(r.body) },
  { p: '/admin/', t: 'Halaman /admin/ dapat diakses', lvl: 0, ok: (r) => r.status === 200 && /login|password|username|dashboard|admin/i.test(r.body) && r.body.length > 200 },
  { p: '/administrator/', t: 'Halaman /administrator/ dapat diakses', lvl: 0, ok: (r) => r.status === 200 && /login|password|joomla|admin/i.test(r.body) && r.body.length > 200 },
  { p: '/wp-login.php', t: 'Halaman login WordPress terpapar', lvl: 0, ok: (r) => /wp-login|wordpress/i.test(r.body) },
  { p: '/wp-config.php', t: 'wp-config.php mungkin terbaca', lvl: 2, ok: (r) => /DB_PASSWORD|DB_NAME/i.test(r.body) },
  { p: '/.env.example', t: 'File .env.example terbuka (bisa bocor struktur rahasia)', lvl: 0, ok: (r) => /[A-Z0-9_]+=/.test(r.body) && !/<html/i.test(r.body) },
  { p: '/config.json', t: 'config.json terbuka ke publik', lvl: 1, ok: (r) => /"(?:password|api_key|secret|token)"/i.test(r.body) },
  { p: '/.htaccess', t: 'File .htaccess terbuka ke publik', lvl: 0, ok: (r) => /RewriteRule|AuthType|Deny from/i.test(r.body) && !/<html/i.test(r.body) },
  { p: '/web.config', t: 'web.config terbuka ke publik', lvl: 1, ok: (r) => /<configuration/i.test(r.body) },
  { p: '/debug/default/view', t: 'Yii debug terbuka ke publik', lvl: 1, ok: (r) => /Yii Debugger|debug/i.test(r.body) },
  { p: '/_profiler/', t: 'Symfony profiler terbuka ke publik', lvl: 1, ok: (r) => /Symfony Profiler|sf-toolbar/i.test(r.body) },
  { p: '/server-info', t: 'Apache server-info terbuka', lvl: 1, ok: (r) => /Apache Server Information/i.test(r.body) },
  { p: '/.git/config', t: 'Repositori .git terbuka ke publik', ok: (r) => /\[core\]/.test(r.body) },
  { p: '/backup.sql.gz', t: 'Dump database terkompresi terbuka', ok: (r) => r.status === 200 && r.body.length > 100 && !/<html/i.test(r.body.slice(0, 200)) },
  { p: '/storage/logs/laravel.log', t: 'Log Laravel terbuka ke publik', lvl: 1, ok: (r) => /local\.ERROR|stacktrace|production\.ERROR/i.test(r.body) },
  { p: '/api/docs', t: 'Dokumentasi API terbuka', lvl: 0, ok: (r) => /swagger|openapi|api documentation/i.test(r.body) },
  { p: '/graphql', t: 'Endpoint GraphQL terpapar', lvl: 0, ok: (r) => r.status === 200 && (/graphql|__schema|query\s*\{/i.test(r.body) || r.ct.includes('json')) },
  {
    p: '/.well-known/security.txt',
    ok: (r) => /^Contact:/mi.test(r.body),
    missing: { lvl: 0, rule: 'securitytxt', text: 'security.txt tidak ada (kontak pelaporan celah)' },
  },
];

/* ---------- Pola bocor di respons web ---------- */

export const ERR_LEAK =
  /Traceback \(most recent call last\)|Fatal error:.{0,200}on line \d+|Warning:.{0,200}on line \d+|SQLSTATE\[|You have an error in your SQL syntax|ORA-\d{5}|Unhandled Exception|at [\w$.]+ \([^)\n]*:\d+:\d+\)/s;
export const INTERNAL_IP = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/;

/* ---------- Aturan kode (mode berkas) ---------- */

const JS = ['js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx'];
const PY = ['py'];
const PHP = ['php', 'phtml', 'inc'];
const SH = ['sh', 'bash', 'zsh'];
const ANY = ['*'];

// { ext, re, lvl, rule, text }
export const CODE_RULES = [
  { ext: JS, re: /\beval\s*\(/, lvl: 1, rule: 'code-eval', text: 'Memakai eval()' },
  { ext: JS, re: /new\s+Function\s*\(/, lvl: 1, rule: 'code-eval', text: 'Memakai new Function()' },
  { ext: JS, re: /\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[^)\n]*\+)/, lvl: 1, rule: 'code-exec', text: 'Perintah shell dibangun dari string dinamis' },
  { ext: JS, re: /\.(?:innerHTML|outerHTML)\s*=(?!=)|document\.write\s*\(|insertAdjacentHTML\s*\(/, lvl: 1, rule: 'code-xss', text: 'Menyisipkan HTML mentah ke DOM (risiko XSS)' },
  { ext: JS, re: /dangerouslySetInnerHTML/, lvl: 0, rule: 'code-xss', text: 'dangerouslySetInnerHTML dipakai' },
  { ext: JS, re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/, lvl: 1, rule: 'code-tls', text: 'Verifikasi sertifikat TLS dimatikan' },
  { ext: JS, re: /createHash\(\s*['"](?:md5|sha1)['"]\s*\)/, lvl: 0, rule: 'code-hash', text: 'Memakai hash lemah (MD5/SHA-1)' },
  { ext: JS, re: /(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^\n;]{0,100}(?:\$\{|["']\s*\+\s*\w)/i, lvl: 1, rule: 'code-sqli', text: 'Query SQL disusun dengan penyambungan string' },

  { ext: PY, re: /\b(?:eval|exec)\s*\(/, lvl: 1, rule: 'code-eval', text: 'Memakai eval()/exec()' },
  { ext: PY, re: /\bos\.system\s*\(|subprocess\.\w+\([^)\n]*shell\s*=\s*True/, lvl: 1, rule: 'code-exec', text: 'Menjalankan perintah lewat shell' },
  { ext: PY, re: /\bpickle\.loads?\s*\(|yaml\.load\s*\((?![^)\n]*Loader)/, lvl: 1, rule: 'code-deser', text: 'Deserialisasi tidak aman (pickle / yaml.load)' },
  { ext: PY, re: /verify\s*=\s*False/, lvl: 1, rule: 'code-tls', text: 'Verifikasi sertifikat TLS dimatikan' },
  { ext: PY, re: /hashlib\.(?:md5|sha1)\s*\(/, lvl: 0, rule: 'code-hash', text: 'Memakai hash lemah (MD5/SHA-1)' },
  { ext: PY, re: /f["'](?:SELECT|INSERT|UPDATE|DELETE)\b[^"'\n]*\{/i, lvl: 1, rule: 'code-sqli', text: 'Query SQL disusun dengan f-string' },
  { ext: PY, re: /\bDEBUG\s*=\s*True\b/, lvl: 0, rule: 'code-debug', text: 'Mode DEBUG aktif' },

  { ext: PHP, re: /\b(?:eval|assert)\s*\(/, lvl: 1, rule: 'code-eval', text: 'Memakai eval()/assert()' },
  { ext: PHP, re: /\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(/, lvl: 1, rule: 'code-exec', text: 'Menjalankan perintah sistem' },
  { ext: PHP, re: /\bunserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/, lvl: 2, rule: 'code-deser', text: 'unserialize() langsung dari input pengguna' },
  { ext: PHP, re: /\b(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)/, lvl: 2, rule: 'code-lfi', text: 'include/require dari input pengguna' },
  { ext: PHP, re: /\$_(?:GET|POST|REQUEST)\b[^;\n]*\b(?:mysql_query|mysqli_query|->query)\s*\(|\b(?:mysql_query|mysqli_query|->query)\s*\([^;\n]*\$_(?:GET|POST|REQUEST)/, lvl: 2, rule: 'code-sqli', text: 'Input pengguna masuk langsung ke query SQL' },
  { ext: PHP, re: /\bmd5\s*\(/, lvl: 0, rule: 'code-hash', text: 'Memakai hash lemah (MD5)' },

  { ext: SH, re: /curl[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b/, lvl: 1, rule: 'code-shell', text: 'Skrip unduhan langsung dijalankan lewat pipe ke shell' },
  { ext: ['yml', 'yaml'], re: /^\s*privileged:\s*true\b/m, lvl: 2, rule: 'iac-priv', text: 'Container berjalan dengan privileged: true' },
  { ext: ['yml', 'yaml'], re: /\/var\/run\/docker\.sock/, lvl: 2, rule: 'iac-priv', text: 'docker.sock di-mount ke container (setara akses root ke host)' },
  { ext: ['yml', 'yaml'], re: /hostNetwork:\s*true|network_mode:\s*["']?host\b/, lvl: 1, rule: 'iac-priv', text: 'Container memakai jaringan host' },
  { ext: ['yml', 'yaml'], re: /allowPrivilegeEscalation:\s*true|runAsUser:\s*0\b/, lvl: 1, rule: 'iac-priv', text: 'Container boleh naik hak akses atau berjalan sebagai root' },
  { ext: ['yml', 'yaml'], re: /^\s*-\s*["']?(?:0\.0\.0\.0:)?(?:3306|5432|6379|27017|9200|11211|5984):\d+["']?\s*$/m, lvl: 1, rule: 'iac-port', text: 'Port database dipublikasikan ke semua interface (bukan 127.0.0.1)' },
  { ext: ['yml', 'yaml'], re: /^\s*image:\s*\S+:latest\b/m, lvl: 0, rule: 'docker-latest', text: 'Image memakai tag :latest' },
  { ext: ['tf'], re: /from_port\s*=\s*(?:22|3389|3306|5432)\b[\s\S]{0,200}0\.0\.0\.0\/0/, lvl: 2, rule: 'iac-open', text: 'Port administrasi/database terbuka ke seluruh internet (0.0.0.0/0)' },
  { ext: ['tf'], re: /cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0\/0"/, lvl: 1, rule: 'iac-open', text: 'Aturan jaringan terbuka ke 0.0.0.0/0' },
  { ext: ['tf'], re: /publicly_accessible\s*=\s*true|acl\s*=\s*"public-read(?:-write)?"/, lvl: 2, rule: 'iac-public', text: 'Resource dibuat publik (database atau bucket)' },
  { ext: ['tf'], re: /encrypted\s*=\s*false/, lvl: 1, rule: 'iac-public', text: 'Enkripsi penyimpanan dimatikan' },
  { ext: ['yml', 'yaml'], re: /add:\s*\[?\s*["']?(?:SYS_ADMIN|NET_ADMIN|ALL)["']?/, lvl: 2, rule: 'iac-priv', text: 'Capability Linux berbahaya ditambahkan (SYS_ADMIN/NET_ADMIN/ALL)' },
  { ext: ['yml', 'yaml'], re: /kind:\s*ClusterRoleBinding[\s\S]{0,300}name:\s*cluster-admin/i, lvl: 2, rule: 'iac-priv', text: 'ClusterRoleBinding memberi akses setara cluster-admin' },
  { ext: ANY, re: /chmod\s+(?:-R\s+)?777\b/, lvl: 1, rule: 'code-perm', text: 'chmod 777 dipakai' },
  { ext: ANY, re: /Access-Control-Allow-Origin['"]?\s*[:,=]\s*['"]?\*/i, lvl: 0, rule: 'cors', text: 'CORS terbuka ke semua origin' },
];

/* ---------- Nama berkas sensitif (mode berkas) ---------- */

// [pola nama, teks, level]
export const SENSITIVE = [
  [/^\.env(\.(?!example$|sample$|template$|dist$).+)?$/i, 'File .env (berisi konfigurasi dan rahasia) ada di folder', 1],
  [/^id_(?:rsa|dsa|ecdsa|ed25519)$/, 'Private key SSH ada di folder', 2],
  [/\.(?:key|p12|pfx|jks|keystore)$/i, 'File kunci/keystore ada di folder', 2],
  [/\.pem$/i, 'File .pem ada di folder (periksa apakah berisi private key)', 1],
  [/^\.htpasswd$/, 'File .htpasswd ada di folder', 2],
  [/^\.git-credentials$/, 'File .git-credentials ada di folder', 2],
  [/^\.(?:npmrc|pypirc)$/, 'File konfigurasi registry (bisa berisi token) ada di folder', 1],
  [/\.tfstate(?:\.backup)?$/i, 'State Terraform (berisi rahasia) ada di folder', 2],
  [/^(?:credentials(?:\.json)?|service[-_]?account.*\.json)$/i, 'File kredensial layanan ada di folder', 2],
  [/\.(?:sqlite3?|db|sql|dump)$/i, 'File database/dump ada di folder', 1],
  [/\.(?:bak|old|orig|swp|swo|tmp)$|~$/i, 'File cadangan/sementara ada di folder', 1],
  [/backup.*\.(?:zip|tar|tgz|gz|rar|7z)$/i, 'Arsip backup ada di folder', 1],
  [/^(?:\.DS_Store|Thumbs\.db)$/i, 'File sampah sistem ada di folder', 0],
];

export const EXEC_EXT = new Set(['exe', 'dll', 'scr', 'msi', 'bat', 'cmd', 'vbs', 'ps1', 'jar', 'apk', 'com']);
export const DOC_EXT = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png', 'gif', 'txt', 'zip']);
export const DOUBLE_EXT = /\.(?:pdf|docx?|xlsx?|jpe?g|png|gif|txt|zip)\.(?:exe|scr|bat|cmd|js|vbs|ps1|com|jar)$/i;
