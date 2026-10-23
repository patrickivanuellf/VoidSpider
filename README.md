# Laba-laba pemindai
<p align="center">
  <a href="https://raw.githubusercontent.com/patrickivanuellf/VoidSpider/main/voidspider_cartoon.mp4">▶ <b>Tonton Video Demo Laba-laba Pemindai</b></a>
</p>

Pemindai audit keamanan untuk **situs web** dan **berkas lokal** milikmu sendiri. Server Node.js memindai target terus-menerus, memberi skor keamanan beserta saran perbaikan, lalu menyiarkan hasilnya lewat SSE ke dasbor berisi graf dan laba-laba bergaris geometri. Setiap kaki laba-laba menjangkau halaman atau berkas yang sedang dipindai server.

Ada dua mode, ditentukan otomatis dari target:

| Mode | Target | Contoh |
| --- | --- | --- |
| Situs web | URL `http(s)://` | `node server.js https://situsmu.com --saya-pemilik-situs` |
| Berkas lokal | Path folder atau satu berkas | `node server.js ./proyek-saya` |

## Menjalankan

Butuh Node.js 18.14 atau lebih baru.

```bash
npm install
node server.js https://situsmu.com --saya-pemilik-situs   # audit situs
node server.js ./folder-atau-berkas                       # audit berkas lokal
```

Buka http://127.0.0.1:3000. Flag `--saya-pemilik-situs` wajib untuk situs di luar localhost, sebagai pengingat bahwa pemindai ini hanya untuk situs yang kamu miliki atau yang sudah mengizinkan pengujian.

Server hanya memindai satu target, yaitu yang kamu berikan saat menjalankan. Dasbor tidak bisa mengubah target, jadi alat ini tidak bisa dipakai sebagai pemindai terbuka.

## Pengaturan (variabel lingkungan)

| Variabel | Bawaan | Fungsi |
| --- | --- | --- |
| `PORT` | 3000 | Port dasbor |
| `BIND` | 127.0.0.1 | Alamat yang didengarkan. Biarkan loopback kecuali kamu menaruh autentikasi di depannya |
| `INTERVAL` | 90 (situs), 30 (berkas) | Jeda antar siklus pemindaian, dalam detik |
| `CONCURRENCY` | 2 (situs), 3 (berkas) | Jumlah kaki yang memindai bersamaan (1 sampai 8) |
| `MAX_PAGES` | 200 (situs), 400 (berkas) | Batas jumlah node (halaman, berkas, folder, domain luar) |
| `DELAY_MS` | 280 (situs), 30 (berkas) | Jeda antar permintaan per kaki, supaya server tidak terbebani |
| `TIMEOUT_MS` | 10000 | Batas waktu tiap permintaan |

Contoh: `INTERVAL=300 CONCURRENCY=2 node server.js https://situsmu.com --saya-pemilik-situs`

## Dasbor

Tampilannya terinspirasi visualisasi pembaca prompt: tiap halaman situs menjadi satu gugus awan kata.

- Setiap gugus adalah satu halaman. Titik-titik di dalamnya adalah kata-kata dari halaman itu (maksimal 40 kata unik per halaman), dengan keterangan seperti `271/271 words · done`.
- Abu-abu berarti belum dibaca. Cyan berarti sedang dibaca, biru berarti aman, dan pink berarti ditandai. Tag pink di atas gugus menunjukkan jenis temuan, misalnya `csp`, `csrf`, `injection`, atau `exposed`.
- Makhluk di tengah berbadan oval gelap dengan inti pink dan serabut halus yang mengipas. Setiap halaman yang dipindai ditembak bundel tentakel manik-manik, dan badannya tertarik mendekat ke gugus itu. Tag biru muncul di kata yang sedang disentuh.
- Judul besar di pojok kiri atas menunjukkan halaman yang sedang dibaca. Layar berkedip merah saat ada temuan kritis baru.
- Kamera mengikuti makhluknya. Tombol "Lihat semua" menampilkan seluruh peta, dan tombol yang sama mengembalikan ke mode ikuti.
- Seret gugus untuk memindahkannya, seret latar untuk menggeser, gulir untuk zoom, klik dua kali di latar untuk mengembalikan tampilan.

Kata-kata halaman hanya dikirim ke dasbor lokalmu. Hanya kata berhuruf (4 sampai 14 huruf) yang diambil, dan halaman yang terdeteksi memuat kunci rahasia tidak dikirimi kata sama sekali.

## Tampilan dasbor

Kanvas memenuhi seluruh layar, dengan bilah atas (target, jam misi `T+`, UTC, status koneksi) dan panel telemetri di sisi kanan berisi skor, hitungan temuan, siaran langsung, dan daftar temuan terbuka.

- **Seret node** untuk memindahkannya, posisinya terkunci di tempat. **Klik 2x node** untuk melepas kuncinya. **Klik 2x latar** untuk mereset kamera.
- **Roda mouse** untuk zoom, seret latar untuk menggeser. Tombol **Lihat semua** memuat seluruh graf ke layar.
- **Tombol H** atau tombol `▸` menyembunyikan panel. Graf otomatis berpindah ke tengah area yang tersisa.
- Di layar sempit (di bawah 860 px), panel berubah menjadi lembar di bagian bawah.

## Skor dan laporan

Setiap temuan punya tingkat (info, sedang, kritis) dan **saran perbaikan**. Dari temuan unik dihitung skor 0 sampai 100 dengan nilai A sampai F, tampil di pojok dasbor. Bobotnya: kritis 10, sedang 3, info 1, dengan penurunan yang melandai supaya satu situs besar tidak otomatis nol.

Laporan bisa diunduh sebagai `/report.json` (untuk diproses mesin) atau `/report.md` (untuk dibaca atau dilampirkan). Mode berkas menambahkan hash SHA-256 tiap berkas ke laporan JSON, berguna untuk memeriksa apakah berkas berubah.

Setiap siklus dibandingkan dengan siklus sebelumnya. Temuan baru dan temuan yang sudah teratasi muncul di siaran langsung.

## Yang diperiksa: mode situs

Semua pemeriksaan bersifat pasif: hanya permintaan GET biasa dan membaca respons, tanpa percobaan eksploitasi.

- Header keamanan di halaman utama: CSP (termasuk CSP yang terlalu longgar: `unsafe-inline`, `unsafe-eval`, wildcard), proteksi clickjacking, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS (termasuk `max-age` terlalu pendek), serta header yang membuka versi server.
- Cookie tanpa Secure, HttpOnly (untuk cookie sesi), SameSite, atau `SameSite=None` tanpa Secure.
- Mixed content, form sandi tanpa token CSRF, form sandi dengan method GET, form yang mengirim ke http, halaman sandi tanpa `Cache-Control: no-store`.
- Skrip dan stylesheet pihak ketiga tanpa SRI, meta generator yang membuka versi CMS.
- Tautan putus (4xx), error server (5xx), respons lambat, dan halaman yang membocorkan stack trace atau error database.
- Directory listing, alamat IP internal di HTML, dan source map JavaScript yang terbuka.
- File sensitif yang terbuka, dicek lewat permintaan ke path umum seperti `/.env`, `/.git/config`, `/.aws/credentials`, `/backup.sql`, `/actuator/env`, `/phpmyadmin/`, `/wp-json/wp/v2/users`. Isi responsnya divalidasi, jadi halaman fallback SPA tidak dianggap temuan. `security.txt` yang tidak ada dicatat sebagai info.
- Kunci rahasia yang terlihat di HTML, JS, dan CSS (AWS, GitHub, Stripe, Slack, SendGrid, npm, JWT, connection string database, private key, dan sejenisnya). Nilainya tidak disimpan atau dikirim ke dasbor, hanya jenisnya.
- Teks tersembunyi (komentar HTML, elemen `display:none`, karakter tag Unicode tak terlihat) yang berisi pola prompt injection.
- Masa berlaku sertifikat TLS dan pengalihan http ke https.

## Yang diperiksa: mode berkas

Audit statis. Pemindai hanya membaca isi berkas: tidak menjalankan apa pun, tidak mengikuti symlink, dan `node_modules` dilewati. Nilai rahasia yang ditemukan tidak pernah disimpan atau ditampilkan, hanya jenis dan nomor barisnya.

- **Berkas sensitif:** `.env`, private key SSH, `.pem`/`.key`/keystore, `.htpasswd`, `.npmrc`, state Terraform, file kredensial layanan, dump database, cadangan (`.bak`, `.old`, `.swp`), dan arsip backup. Berkas yang tercantum di `.gitignore` diturunkan jadi info, karena memang tidak ikut ter-commit.
- **Rahasia di dalam isi berkas:** semua pola kunci di atas, ditambah kredensial yang tertulis langsung di kode (`password = "..."`).
- **Berkas mencurigakan:** biner eksekusi, ekstensi ganda (`invoice.pdf.exe`), dan dokumen/gambar yang isinya sebenarnya biner eksekusi.
- **Izin:** berkas atau folder yang bisa ditulis siapa saja, dan berkas rahasia yang terbaca pengguna lain.
- **Pola kode berisiko** (JS/TS, Python, PHP, shell): `eval`, perintah shell dari string dinamis, SQL yang disusun lewat penyambungan string, input pengguna langsung ke query/include/unserialize, HTML mentah ke DOM, verifikasi TLS dimatikan, hash lemah, `curl | sh`, `chmod 777`. Berkas minified dilewati untuk aturan ini.
- **Karakter tak terlihat:** karakter kontrol bidi (Trojan Source), zero-width, dan karakter tag Unicode yang bisa menyelundupkan prompt.
- **Prompt injection** di teks, Markdown, dan komentar atau elemen tersembunyi di HTML.
- **Proyek:** skrip install di `package.json`, dependensi tanpa kunci versi, lockfile yang tidak ada, `Dockerfile` tanpa `USER` non-root atau memakai `:latest`, dan folder `.git`/`.svn` yang ikut ada.

## Fitur lanjutan

**Kerentanan dependensi (CVE).** Mode berkas membaca `package-lock.json`, `requirements.txt` (versi yang dikunci dengan `==`), dan `composer.lock`, lalu mencocokkannya dengan database OSV.dev. Yang dikirim hanya nama paket, ekosistem, dan versi. Hasilnya diberi tingkat dari skor CVSS dan disertai versi perbaikan. Kalau OSV tidak terjangkau, muncul satu catatan info dan pemindaian tetap lanjut.

**DNS dan email (mode situs).** SPF, DMARC, DKIM (selector umum), CAA, dan DNSSEC. Daftar subdomain diambil dari Certificate Transparency (crt.sh), lalu tiap subdomain dicek apakah CNAME-nya menunjuk ke layanan yang sudah tidak ada atau halaman "belum diklaim" milik GitHub Pages, Heroku, S3, Azure, dan sejenisnya (risiko subdomain takeover). Subdomain muncul sebagai node abu-abu di graf, dan masa berlaku sertifikatnya ikut diperiksa. Pemeriksaan ini berjalan paling sering sekali per jam. DNSSEC memakai DNS-over-HTTPS Cloudflare, matikan dengan `DNS_DOH=0`.

**TLS mendalam (mode situs).** TLS 1.0/1.1 yang masih diterima, dukungan TLS 1.3, cipher lemah (3DES, RC4, NULL), rantai sertifikat (self-signed, intermediate hilang, nama tidak cocok), ukuran kunci RSA, dan masa berlaku sertifikat termasuk intermediate.

**Webshell dan kode diacak (mode berkas).** Pola webshell PHP, `eval` atas data yang di-decode, file gambar yang berisi PHP, packer dan obfuscator JavaScript, penambang kripto, iframe tersembunyi, pengalihan khusus pengunjung mesin pencari (cloaking), dan pola reverse shell. Aturan memakai gaya YARA: sebuah aturan cocok bila semua pola `all` ada dan tidak ada pola `none`. Aturan milikmu bisa ditaruh di `rules/*.json` tanpa mengubah kode (lihat `rules/contoh-aturan.json`, atau atur folder lain lewat `RULES_DIR`).

**Analisis aliran data JavaScript.** Memakai AST (acorn). Input dari `req.query`, `req.body`, `req.params`, `location`, dan sejenisnya dilacak lewat variabel, template string, dan penyambungan, lalu dicek apakah sampai ke `exec`, `eval`, path berkas, query SQL, `innerHTML`, atau redirect. Fungsi pembersih seperti `parseInt`, `path.basename`, dan `encodeURIComponent` memutus aliran. Pelacakan hanya dalam satu berkas, jadi anggap hasilnya petunjuk. Python dan PHP masih memakai pola, bukan AST.

**Infrastructure as code.** `docker-compose.yml` dan manifest Kubernetes (privileged, docker.sock, hostNetwork, port database yang terbuka ke semua interface, image `:latest`), serta Terraform (port administrasi terbuka ke 0.0.0.0/0, resource publik, enkripsi mati).

**Riwayat Git.** Kalau folder target punya `.git`, riwayat commit (maksimal 300) diperiksa untuk kunci yang pernah ter-commit walaupun sudah dihapus dari berkas sekarang. Hanya jenis kunci, hash commit, dan path yang dilaporkan, nilainya tidak. Pemeriksaan ini jalan lagi hanya saat HEAD berubah.

**Pemantauan perubahan (drift).** Siklus pertama merekam baseline di folder `data/`. Siklus berikutnya melaporkan berkas kode baru, berkas yang isinya berubah, dan berkas yang hilang (mode berkas), serta domain skrip atau iframe pihak ketiga yang baru muncul (mode situs). Baseline tidak berubah sendiri: kalau perubahannya memang sah, jalankan ulang dengan `--terima-perubahan`. Mode `--once` tidak memakai baseline kecuali diberi `--pakai-baseline`.

**Notifikasi Telegram.** Atur `TELEGRAM_BOT_TOKEN` dan `TELEGRAM_CHAT_ID` (dan opsional `NOTIFY_WEBHOOK`). Siklus pertama mengirim satu ringkasan, setelah itu hanya temuan baru yang berkelas kritis (ubah dengan `NOTIFY_MIN_LEVEL=1`), tanpa pengulangan. Token tidak pernah dicetak, dan teks temuan tidak pernah memuat nilai rahasia.

**Serangan masuk (SSH dan honeypot).** `--ssh-log /var/log/auth.log` membaca login SSH yang gagal dan berhasil. `--honeypot-log` membaca log JSON Cowrie. Panel "serangan masuk" menampilkan IP teratas, brute force (5 kegagalan dalam semenit) muncul di siaran langsung dan Telegram, dan login berhasil setelah beberapa kegagalan ditandai sebagai peringatan. Sandi yang dicoba penyerang tidak pernah disimpan atau ditampilkan. Membaca `/var/log/auth.log` biasanya perlu hak akses (grup `adm` atau sudo).

**Agent triase (opsional, nonaktif secara bawaan).** Dengan `--agent` dan `ANTHROPIC_API_KEY`, temuan sedang ke atas dinilai oleh Claude: nyata, kemungkinan positif palsu, atau perlu tinjauan, lengkap dengan prioritas dan alasan. Lalu agent menyusun urutan perbaikan. Aturan privasinya:

- Yang dikirim ke API hanya teks temuan dan potongan kode pendek (sekitar 5 baris) yang kunci rahasianya sudah diganti `[REDAKSI]`. Temuan rahasia tidak dikirim bersama potongan kode.
- Isi berkas dan halaman dikirim sebagai data tidak tepercaya di dalam blok `<data>` dengan instruksi untuk tidak mengikuti perintah apa pun di dalamnya. Agent tidak punya alat, tidak bisa mengubah berkas, dan keluarannya divalidasi (verdict dan prioritas di luar rentang dibuang).
- Hasil di-cache, jadi temuan yang tidak berubah tidak dikirim ulang. Batas per siklus: `AGENT_MAX` (30). Model: `AGENT_MODEL` (bawaan `claude-sonnet-5-5`).
- Untuk proyek yang tidak boleh keluar dari mesinmu, jangan pakai `--agent`.

**Mode CI.** `--once` menjalankan satu siklus tanpa dasbor, menulis laporan, lalu keluar dengan kode: `0` bila bersih, `1` bila ada temuan di atau di atas `--fail-on` (`kritis` bawaan, atau `sedang`, `info`, `tidak`), `2` bila alat gagal. Keluaran: `--sarif hasil.sarif` (untuk GitHub Code Scanning), `--json`, dan `--md`. Contoh workflow ada di `examples/github-action.yml`.

```bash
node server.js . --once --sarif hasil.sarif --md laporan.md --fail-on kritis
node server.js . --once --offline          # tanpa panggilan keluar (CVE, DNS, CT dilewati)
node server.js https://situsmu.com --saya-pemilik-situs --ssh-log /var/log/auth.log
```

Variabel lingkungan tambahan: `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `NOTIFY_WEBHOOK`, `NOTIFY_MIN_LEVEL`, `ANTHROPIC_API_KEY`, `AGENT_MODEL`, `AGENT_MAX`, `DATA_DIR`, `RULES_DIR`, `OSV_URL`, `DNS_DOH`, `OFFLINE`.

Menjalankan tes: `npm test` (21 tes, tanpa jaringan: layanan luar diganti tiruan).

## Fitur lanjutan v5

**JWT (pasif, tanpa verifikasi).** Men-decode header dan payload token JWT yang ditemukan di halaman atau berkas: `alg:none` (tanda tangan tidak diverifikasi sama sekali), token tanpa klaim `exp`, masa berlaku yang sangat panjang, dan nama klaim yang tampak sensitif (`password`, `ssn`, dan sejenisnya). Tidak pernah memverifikasi tanda tangan dan tidak butuh secret.

**Kredensial generik lewat entropi.** Jaring tambahan di luar pola kunci yang dikenal (AWS, GitHub, Stripe, dan seterusnya): kata kunci seperti `apiKey`, `secret`, `token` diikuti nilai berkutip yang tampak acak (entropi tinggi, campuran huruf besar/kecil/angka). Hash heksadesimal, UUID, dan angka biasa sengaja dikecualikan. Ini level sedang (bukan kritis) dan secara eksplisit disebut heuristik di saran perbaikannya, karena bisa salah — pelajaran dari kasus pola `sk-` yang pernah terlalu longgar.

**Fingerprint WAF/CDN dan deteksi diblokir (mode situs).** Mengenali Cloudflare, Sucuri, Akamai, Imperva, AWS WAF, dan Fastly dari header respons (info, bukan temuan negatif). Kalau lebih dari 30% halaman kembali dengan 403/429, muncul catatan di siaran langsung bahwa pemindai kemungkinan diblokir dan hasilnya bisa tidak lengkap — ini menjawab pertanyaan "kenapa skornya bagus padahal baru sedikit yang diperiksa".

**Probe web yang bisa diperluas.** Selain path bawaan, kamu bisa menambah path sensitif sendiri lewat `rules/probes/*.json` tanpa mengubah kode:
```json
[{ "path": "/admin/debug", "text": "Halaman debug admin ditemukan", "lvl": 1, "bodyMatch": "Debug Console", "ctMatch": "text/html" }]
```

**Enumerasi subdomain umum (mode situs).** Selain daftar dari Certificate Transparency, sekitar 35 nama subdomain umum (`api`, `staging`, `admin`, `git`, dan sejenisnya) langsung dicoba lewat resolver DNS publik. Ini hanya resolusi DNS, tidak pernah mengirim permintaan ke server web target secara langsung untuk subdomain yang baru ditemukan ini.

**Kubernetes dan RBAC.** Dua aturan tambahan untuk manifest YAML: capability Linux berbahaya (`SYS_ADMIN`, `NET_ADMIN`, `ALL`) dan `ClusterRoleBinding` yang memberi akses setara `cluster-admin`.

## Evaluasi (untuk naskah/skripsi)

Folder `eval/` berisi korpus berlabel, harness yang memanggil `auditFile()` produksi secara
langsung, dan perbandingan dengan Gitleaks serta Semgrep pada korpus yang sama, ditambah validasi
pada data independen (381 webshell PHP nyata, dan kode sumber expressjs/express sebagai baseline
bersih). Metodologi lengkap, tabel hasil, lima bug yang terbongkar lewat evaluasi ini, dan daftar
keterbatasan ada di `eval/HASIL.md` — tulisan itu dirancang untuk langsung diadaptasi ke bagian
Metodologi dan Hasil & Pembahasan naskah SINTA. Menjalankan ulang semua angkanya: lihat §7 di
dokumen itu.

## Audit terautentikasi (di balik login)

Secara bawaan, mode situs hanya melihat halaman publik. Untuk mengaudit halaman yang butuh login
(dashboard admin, area anggota, API internal), beri sesi atau token milikmu sendiri lewat:

```bash
# Cookie sesi (dari DevTools browser -> Application -> Cookies, setelah kamu login manual)
node server.js https://situsmu.com --saya-pemilik-situs --cookie "sesi=abcdef; lainnya=123"

# Header Authorization / API key (bisa diulang untuk beberapa header)
node server.js https://situsmu.com --saya-pemilik-situs --header "Authorization: Bearer eyJ..." --header "X-Api-Key: ..."
```

Header ini dikirim ke **setiap** permintaan selama audit berjalan, jadi pemindai bertindak persis
sebagai akun yang sesinya kamu berikan. Beberapa hal penting:

- **Pakai sesi milikmu sendiri**, jangan sesi orang lain walaupun kamu punya aksesnya.
- Kalau sesi itu akun admin, pemindai akan melihat (dan bisa menandai) apa pun yang admin bisa
  lihat. Pertimbangkan membuat akun uji terpisah dengan hak akses terbatas kalau ada pilihan.
- Token tidak pernah disimpan ke berkas laporan atau baseline, hanya dipakai saat permintaan
  berjalan. Tapi tetap perlakukan perintah Terminal yang berisi token sebagai rahasia — jangan
  tempel ke riwayat shell publik atau screenshot.
- Ini tetap **audit konfigurasi pasif**, bukan pengujian otorisasi aktif: alat ini tidak mencoba
  mengakses data akun lain atau menebak apakah kontrol akses antar-pengguna (IDOR) berfungsi benar.
  Untuk pengujian aktif semacam itu, lihat bagian berikutnya.

## Yang tidak dibangun di sini, dan ke mana sebaiknya pergi

Alat ini sengaja berhenti di audit pasif: tidak ada percobaan login, tidak ada payload serangan
(SQLi/XSS aktif), tidak ada fuzzing, tidak ada percobaan bypass otorisasi. Itu keputusan desain,
bukan keterbatasan teknis -- begitu kemampuan menyerang ada di kode, ia bekerja sama persis
terhadap situs siapa pun yang diarahkan ke sana, bukan cuma situs milikmu.

Untuk pengujian aktif yang sungguhan (DAST), alat ini bisa disambungkan ke **OWASP ZAP** -- lihat
bagian berikutnya. ZAP tidak dijalankan atau dipasang oleh alat ini; kamu menjalankan ZAP sendiri
di mesinmu, dan alat ini hanya memanggil REST API-nya.

## Integrasi OWASP ZAP (pengujian aktif, opsional)

**1. Jalankan daemon ZAP sendiri** (bukan tugas alat ini). Paling gampang lewat Docker:

```bash
docker run -u zap -p 8080:8080 zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.disablekey=true
```

Atau pasang langsung (butuh Java): unduh dari https://www.zaproxy.org/download/ lalu
`zap.sh -daemon -port 8080 -config api.disablekey=true`. Kalau kamu set API key (disarankan untuk
apa pun selain localhost), pakai `-config api.key=KUNCIMU` lalu teruskan lewat `--zap-api-key`.

**2. Spider + passive scan (aman, setara risiko dengan pemindai kita sendiri)**

```bash
node server.js https://situsmu.com --saya-pemilik-situs --zap http://127.0.0.1:8080
```

ZAP merayapi target dan membaca alert dari pemeriksaan pasifnya (header, cookie, versi, dan
sejenisnya -- banyak tumpang tindih dengan pemeriksaan kita sendiri, tapi dengan basis aturan yang
sudah matang dan dipakai luas). Tidak ada payload serangan dikirim pada mode ini.

**3. Active scan (ZAP MENGIRIM payload serangan sungguhan -- SQLi, XSS, dan sejenisnya)**

```bash
node server.js https://staging.situsmu.com --saya-pemilik-situs \
  --zap http://127.0.0.1:8080 --zap-active-scan --saya-paham-risiko-active-scan
```

Baca ini sebelum menjalankan:

- **Jalankan ke staging, bukan produksi yang sedang dipakai orang.** Active scan mengisi form,
  mencoba injeksi di tiap parameter yang ditemukan, dan bisa memicu efek samping nyata (membuat
  data sampah, mengirim email uji, memicu alur pembayaran, dan sejenisnya) kalau endpoint-nya
  tidak idempoten.
- **Bisa memakan waktu lama** (menit sampai jam, tergantung ukuran situs) dan menghasilkan lalu
  lintas besar -- beri tahu dulu kalau situsnya di belakang WAF/rate-limit, supaya tidak disangka
  serangan sungguhan dan memicu block otomatis.
- Dua flag (`--zap-active-scan` **dan** `--saya-paham-risiko-active-scan`) sengaja dibutuhkan
  berdua. Tanpa `--saya-paham-risiko-active-scan`, server menolak jalan dan menampilkan
  peringatan ini lagi.
- Alert ZAP masuk ke laporan dengan aturan `zap`, dikelompokkan per jenis alert (supaya satu
  masalah yang muncul di ratusan halaman tidak membanjiri dasbor), dengan saran perbaikan dari ZAP
  sendiri. Level risikonya diturunkan satu tingkat kalau ZAP sendiri melaporkan confidence rendah.
- Active scan hanya dipicu **sekali per proses** (bukan tiap siklus pindai ulang), karena ia berat
  dan tidak idempoten untuk diulang terus-menerus.

Kalau `--zap` diberi tapi daemon ZAP tidak terjangkau, satu baris error muncul di siaran langsung
dan konsol, lalu audit lain tetap berjalan seperti biasa (ZAP bukan prasyarat).

## Fitur lanjutan v5

**JWT (pasif, tanpa verifikasi).** Men-decode header dan payload token JWT yang ditemukan di halaman atau berkas: `alg:none` (tanda tangan tidak diverifikasi sama sekali), token tanpa klaim `exp`, masa berlaku yang sangat panjang, dan nama klaim yang tampak sensitif (`password`, `ssn`, dan sejenisnya). Tidak pernah memverifikasi tanda tangan dan tidak butuh secret.

**Kredensial generik lewat entropi.** Jaring tambahan di luar pola kunci yang dikenal (AWS, GitHub, Stripe, dan seterusnya): kata kunci seperti `apiKey`, `secret`, `token` diikuti nilai berkutip yang tampak acak (entropi tinggi, campuran huruf besar/kecil/angka). Hash heksadesimal, UUID, dan angka biasa sengaja dikecualikan. Ini level sedang (bukan kritis) dan secara eksplisit disebut heuristik di saran perbaikannya, karena bisa salah — pelajaran dari kasus pola `sk-` yang pernah terlalu longgar.

**Fingerprint WAF/CDN dan deteksi diblokir (mode situs).** Mengenali Cloudflare, Sucuri, Akamai, Imperva, AWS WAF, dan Fastly dari header respons (info, bukan temuan negatif). Kalau lebih dari 30% halaman kembali dengan 403/429, muncul catatan di siaran langsung bahwa pemindai kemungkinan diblokir dan hasilnya bisa tidak lengkap — ini menjawab pertanyaan "kenapa skornya bagus padahal baru sedikit yang diperiksa".

**Probe web yang bisa diperluas.** Selain path bawaan, kamu bisa menambah path sensitif sendiri lewat `rules/probes/*.json` tanpa mengubah kode:
```json
[{ "path": "/admin/debug", "text": "Halaman debug admin ditemukan", "lvl": 1, "bodyMatch": "Debug Console", "ctMatch": "text/html" }]
```

**Enumerasi subdomain umum (mode situs).** Selain daftar dari Certificate Transparency, sekitar 35 nama subdomain umum (`api`, `staging`, `admin`, `git`, dan sejenisnya) langsung dicoba lewat resolver DNS publik. Ini hanya resolusi DNS, tidak pernah mengirim permintaan ke server web target secara langsung untuk subdomain yang baru ditemukan ini.

**Kubernetes dan RBAC.** Dua aturan tambahan untuk manifest YAML: capability Linux berbahaya (`SYS_ADMIN`, `NET_ADMIN`, `ALL`) dan `ClusterRoleBinding` yang memberi akses setara `cluster-admin`.

## Evaluasi (untuk naskah/skripsi)

Folder `eval/` berisi korpus berlabel, harness yang memanggil `auditFile()` produksi secara
langsung, dan perbandingan dengan Gitleaks serta Semgrep pada korpus yang sama, ditambah validasi
pada data independen (381 webshell PHP nyata, dan kode sumber expressjs/express sebagai baseline
bersih). Metodologi lengkap, tabel hasil, lima bug yang terbongkar lewat evaluasi ini, dan daftar
keterbatasan ada di `eval/HASIL.md` — tulisan itu dirancang untuk langsung diadaptasi ke bagian
Metodologi dan Hasil & Pembahasan naskah SINTA. Menjalankan ulang semua angkanya: lihat §7 di
dokumen itu.

## Audit terautentikasi (di balik login)

Secara bawaan, mode situs hanya melihat halaman publik. Untuk mengaudit halaman yang butuh login
(dashboard admin, area anggota, API internal), beri sesi atau token milikmu sendiri lewat:

```bash
# Cookie sesi (dari DevTools browser -> Application -> Cookies, setelah kamu login manual)
node server.js https://situsmu.com --saya-pemilik-situs --cookie "sesi=abcdef; lainnya=123"

# Header Authorization / API key (bisa diulang untuk beberapa header)
node server.js https://situsmu.com --saya-pemilik-situs --header "Authorization: Bearer eyJ..." --header "X-Api-Key: ..."
```

Header ini dikirim ke **setiap** permintaan selama audit berjalan, jadi pemindai bertindak persis
sebagai akun yang sesinya kamu berikan. Beberapa hal penting:

- **Pakai sesi milikmu sendiri**, jangan sesi orang lain walaupun kamu punya aksesnya.
- Kalau sesi itu akun admin, pemindai akan melihat (dan bisa menandai) apa pun yang admin bisa
  lihat. Pertimbangkan membuat akun uji terpisah dengan hak akses terbatas kalau ada pilihan.
- Token tidak pernah disimpan ke berkas laporan atau baseline, hanya dipakai saat permintaan
  berjalan. Tapi tetap perlakukan perintah Terminal yang berisi token sebagai rahasia — jangan
  tempel ke riwayat shell publik atau screenshot.
- Ini tetap **audit konfigurasi pasif**, bukan pengujian otorisasi aktif: alat ini tidak mencoba
  mengakses data akun lain atau menebak apakah kontrol akses antar-pengguna (IDOR) berfungsi benar.
  Untuk pengujian aktif semacam itu, lihat bagian berikutnya.

## Yang tidak dibangun di sini, dan ke mana sebaiknya pergi

Alat ini sengaja berhenti di audit pasif: tidak ada percobaan login, tidak ada payload serangan
(SQLi/XSS aktif), tidak ada fuzzing, tidak ada percobaan bypass otorisasi. Itu keputusan desain,
bukan keterbatasan teknis — begitu kemampuan menyerang ada di kode, ia bekerja sama persis
terhadap situs siapa pun yang diarahkan ke sana, bukan cuma situs milikmu.

Untuk pengujian aktif yang sungguhan (DAST), jalur yang benar adalah menyambungkan ke alat yang
memang dirancang untuk itu dengan model persetujuan eksplisit, seperti **OWASP ZAP**. Ini bisa
diorkestrasi dari luar alat ini (ZAP baseline/active scan terhadap target yang sama, hasilnya
digabung ke laporan) tanpa menulis ulang logika eksploitasi. Ini belum diimplementasikan di repo
ini; kalau kamu butuh, itu pengembangan terpisah.

## Batas yang sengaja dipasang

Alat ini tidak mengirim payload serangan, tidak mencoba login, tidak melakukan fuzzing, dan tidak memindai port. Semua pemeriksaan pasif atau berupa permintaan biasa ke target milikmu. Itu disengaja, karena alat yang bisa menyerang akan sama bahayanya di tangan orang lain. Untuk berlatih pengujian aktif, pakai lab lokal seperti OWASP Juice Shop.

## Memakai di VPS

Biarkan `BIND=127.0.0.1` dan akses dasbor lewat SSH tunnel:

```bash
ssh -L 3000:127.0.0.1:3000 user@vps-mu
```

Jalankan terus-menerus dengan `pm2 start server.js --name laba-laba -- https://situsmu.com --saya-pemilik-situs` atau service systemd. Kalau dasbor harus bisa dibuka lewat domain, taruh di belakang reverse proxy dengan autentikasi. Dasbor ini tidak punya login sendiri.

## Batasan

- Mode situs hanya melihat apa yang terjangkau dari luar. Halaman di balik login, kode server, dan konfigurasi internal tidak terlihat.
- Mode berkas adalah analisis statis berbasis pola. Ia tidak melacak aliran data, tidak memeriksa kerentanan dependensi (CVE), dan tidak menggantikan SAST atau `npm audit`.
- Halaman yang isinya dibuat JavaScript di browser (SPA) hanya terbaca sebatas HTML awalnya. Untuk itu crawler perlu browser headless seperti Playwright.
- Pola deteksi berbasis aturan sederhana, jadi bisa meleset ke dua arah (positif palsu maupun terlewat). Anggap hasilnya sebagai daftar periksa awal, bukan audit keamanan penuh.
- Robots.txt tidak dipakai sebagai pembatas, karena tujuannya memang melihat apa yang bisa diakses publik di situsmu sendiri.
- Rahasia yang sudah terlanjur terlihat harus dianggap bocor: cabut dan ganti, jangan hanya dihapus dari berkas.

## Struktur

```
server.js            mode, crawler situs, penelusur berkas, SSE, mode CI, agent, notifikasi
lib/rules.js         pola deteksi, probe, saran perbaikan, rumus skor
lib/filescan.js      audit statis berkas dan folder lokal
lib/ast.js           analisis aliran data JavaScript (acorn)
lib/malware.js       webshell, obfuscation, miner (aturan bergaya YARA, rules/*.json)
lib/deps.js          CVE dependensi lewat OSV.dev
lib/dnsaudit.js      SPF, DMARC, DKIM, CAA, DNSSEC, CT, subdomain takeover
lib/tlsaudit.js      TLS mendalam dan sertifikat subdomain
lib/githistory.js    kunci yang pernah ter-commit
lib/drift.js         baseline dan pemantauan perubahan
lib/notify.js        Telegram dan webhook
lib/intel.js         umpan log SSH dan honeypot Cowrie
lib/agent.js         triase dan urutan perbaikan lewat Claude API (opsional)
lib/sarif.js         keluaran SARIF 2.1.0
public/              dasbor (HUD, panel telemetri, graf laba-laba)
test/                21 tes otomatis
examples/            contoh GitHub Action
rules/               aturan deteksi milikmu (JSON)
```

Endpoint: `/events` (SSE), `/report.json`, `/report.md`.

Menambah aturan baru: tambahkan pola ke `CODE_RULES`, `PROBES`, atau `rules/*.json`, lalu tulis saran perbaikannya di `FIX` dengan kunci yang sama.
