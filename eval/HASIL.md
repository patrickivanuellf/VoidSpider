# Metodologi dan hasil evaluasi: laba-laba pemindai (v6)

Dokumen ini menjawab pertanyaan "apa buktinya alat ini bekerja", dengan kontribusi yang diklaim:
**pemindai pasif multi-lapis (secrets, JWT, webshell, aliran data/taint, IaC) yang dievaluasi secara
komparatif terhadap alat sejenis dan terhadap data independen**, bukan satu teknik deteksi baru.

## 1. Desain evaluasi

Tiga lapis data dipakai, dengan tujuan berbeda, supaya tidak terjadi *data leakage* (melaporkan skor
tinggi pada data yang juga dipakai untuk menyetel aturan):

| Lapis | Data | Dipakai untuk | Tahu dipakai mengembangkan aturan? |
|---|---|---|---|
| 1. Korpus pengembangan | `eval/corpus/` (35 berkas buatan sendiri, berlabel) | Membongkar dan memperbaiki bug selama pengembangan | **Ya** — jangan laporkan skornya sebagai bukti generalisasi |
| 2. Korpus independen (positif) | 381 webshell PHP nyata dari koleksi publik `tennc/webshell` (dirujuk di riset keamanan lain) | Mengukur *recall* pada sampel yang tidak pernah dilihat saat pengembangan | Tidak |
| 3. Korpus independen (negatif) | Kode sumber `expressjs/express` (library produksi nyata) | Mengukur *false positive rate* pada kode yang diketahui bersih | Tidak |

Metrik: TP/FP/FN/TN, precision, recall, F1, dan false positive rate (FPR), dihitung di
`eval/compare.mjs`, `eval/run-wild.mjs`, `eval/run-benign.mjs`. Semua skrip memanggil
`auditFile()` dari `lib/filescan.js` secara langsung — fungsi produksi yang sama persis dipakai
`server.js`, bukan reimplementasi terpisah untuk evaluasi.

## 2. Hasil lapis 1: korpus pengembangan (bukan bukti generalisasi)

| Alat | Cakupan kategori | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|---|---|---|
| laba-laba-pemindai | secrets, jwt, webshell, taint, iac | 21 | 0 | 0 | 14 | 100,0% | 100,0% | 100,0% | 0,0% |
| Gitleaks v8.21.2 | secrets, jwt | 7 | 1 | 1 | 4 | 87,5% | 87,5% | 87,5% | 20,0% |
| Semgrep 1.181.0 (aturan lokal) | taint, webshell, iac | 9 | 0 | 4 | 9 | 100,0% | 69,2% | 81,8% | 0,0% |

Catatan jujur: skor 100% laba-laba-pemindai pada baris ini **tidak dilaporkan sebagai bukti
kinerja** di bagian Hasil naskah, karena korpus ini dipakai untuk memperbaiki lima bug selama
pengembangan (lihat §4). Baris ini hanya menunjukkan bahwa setelah perbaikan, regresi pada kasus
yang sudah diketahui tidak terjadi.

Catatan cakupan: Gitleaks dan Semgrep adalah alat satu-tujuan (secrets-only, SAST generik tanpa
IaC/JWT), sehingga kolom "cakupan kategori" berbeda. Perbandingan precision/recall hanya adil pada
kategori yang sama-sama dicakup; keunggulan laba-laba-pemindai di sini sebagian besar berasal dari
cakupan kategori yang lebih luas (JWT semantik, IaC), bukan semata akurasi per kategori yang sama.

Semgrep dijalankan dengan aturan lokal (`eval/tools/semgrep-rules.yml`), bukan registry
`p/security-audit`, karena lingkungan evaluasi ini tidak punya akses ke `semgrep.dev`. Ini membuat
hasil bisa diulang tanpa bergantung pada aturan registry yang bisa berubah sewaktu-waktu, tapi juga
berarti aturan Semgrep di sini bukan representasi performa terbaiknya; jalankan ulang dengan
`--config p/security-audit` di mesin yang punya akses internet penuh untuk pembanding yang lebih
representatif.

## 3. Hasil lapis 2 dan 3: data independen (bukti generalisasi)

**Recall pada 381 webshell PHP nyata** (koleksi publik, tidak pernah dilihat saat pengembangan):

- Sebelum perbaikan case-sensitivity dan deteksi resolusi fungsi terenkode: **74,5%** (284/381)
- Sesudah: **77,2%** (294/381)

**FPR pada kode produksi nyata** (expressjs/express):

- Folder `lib/` (kode library inti, n=6): **0,0%** (0/6 ditandai)
- Seluruh repo termasuk `examples/` (kode demonstrasi, n=50): **6,0%** (3/50)

Tiga yang ditandai di `examples/` diperiksa manual satu per satu:
1. `res.download(req.params.file.join('/'), { root: FILES_DIR })` — jalur file memang berasal dari
   input pengguna; Express menetralisir *path traversal* lewat opsi `root`, tapi alat kami tidak
   memodelkan semantik opsi itu. Diperlakukan sebagai **positif yang masuk akal untuk ditinjau**,
   bukan kesalahan analisis.
2. `res.redirect('/pet/' + req.params.user_id)` — pola redirect dari input pengguna; risiko
   sebenarnya tergantung apakah nilainya bisa memuat URL penuh, yang tidak bisa dipastikan secara
   statis.
3. `res.send('requested ' + req.params.sub)` — parameter URL dipantulkan langsung ke respons
   `res.send()` (default `Content-Type: text/html` di Express), pola XSS reflektif klasik — ini
   **temuan yang benar**, kebetulan muncul di kode contoh resmi Express yang memang disederhanakan
   untuk pengajaran, bukan dikeraskan untuk produksi.

## 4. Lima bug yang dibongkar oleh metodologi evaluasi ini

Ditulis secara eksplisit karena ini bagian dari kontribusi: menunjukkan bahwa evaluasi sistematis
(bukan sekadar "alat ini jalan") membongkar masalah nyata.

1. **Harness evaluasi awal melewatkan kategori IaC sepenuhnya** (bug di evaluasi, bukan di alat) —
   diperbaiki dengan memanggil `auditFile()` produksi langsung, bukan reimplementasi.
2. **Aturan JWT generik terlalu longgar**: menandai *setiap* JWT yang ditemukan sebagai temuan
   level sedang, termasuk token yang sudah valid dan berumur wajar. Diturunkan ke level info;
   risiko sebenarnya (`alg:none`, tanpa `exp`, klaim sensitif) ditangani modul JWT khusus.
3. **Aturan "kredensial tertulis langsung di kode" menandai placeholder** seperti
   `<ISI_DENGAN_SECRET_ANDA>` dan `xxxxxxxx`. Ditambah validator yang menolak nilai berulang satu
   karakter, dibungkus `< >`, atau memuat kata seperti *changeme*/*placeholder*/*example*.
4. **Taint JavaScript meng-over-taint lewat *property write***: `el.textContent = tainted` membuat
   variabel `el` dianggap tercemar seluruhnya, memicu *false positive* saat `el.outerHTML` dibaca
   kemudian. Properti yang otomatis di-escape (`textContent`, `innerText`, `value`, `nodeValue`)
   dikecualikan dari propagasi.
5. **Taint JavaScript meng-over-taint ke arah sebaliknya**: menulis ke properti bersarang pada
   objek kerangka kerja bersama (`req.pet.name = tercemar`) membuat identifier `req` **itu sendiri**
   dianggap tercemar untuk sisa berkas, sehingga `req.pet.id` di baris lain salah dikaitkan sebagai
   berasal dari `req.body`. Ini ditemukan lewat pengujian pada `expressjs/express`, bukan korpus
   buatan sendiri — bukti konkret nilai pengujian pada kode independen. Diperbaiki dengan melarang
   penulisan properti bersarang mencemari identifier objek bersama (`req`, `res`, `window`,
   `document`, dan sejenisnya).

## 5. Keterbatasan (ancaman terhadap validitas)

- **Fenomena "basis tanda tangan mendeteksi dirinya sendiri".** Memindai kode sumber alat ini sendiri
  (`lib/malware.js`, `lib/rules.js`) menghasilkan banyak "temuan" palsu, karena berkas-berkas itu
  memang **berisi** pola serangan (`coinhive`, `c99shell`, `eval(`) sebagai literal string di dalam
  definisi aturan dan teks saran perbaikan — bukan kode yang benar-benar dieksekusi. Ini analog
  dengan basis data tanda tangan antivirus yang terdeteksi antivirus lain. Jangan audit folder
  `lib/` dan `rules/` milik alat ini sendiri dengan alat sejenis dan mengharapkan hasil bersih.
- **Evasion berbasis Reflection PHP dan variabel-variabel** (`$$x`, `ReflectionClass`,
  `__invoke`) pada koleksi AntSword tidak terdeteksi. Ini butuh analisis semantik PHP yang jauh
  lebih dalam (di luar regex/AST satu-file), dicatat sebagai kerja lanjutan.
- **Taint tracking flow-insensitive dan satu-berkas.** Pelacakan tidak memahami urutan eksekusi
  maupun percabangan, dan berhenti di batas berkas. Ini pilihan desain sadar untuk menjaga
  kecepatan (cocok untuk pemindaian berulang), bukan analisis data-flow lengkap seperti CodeQL.
- **Precision/recall lapis 1 tidak mewakili performa dunia nyata** karena korpusnya kecil (35
  berkas) dan dipakai untuk debugging. Lapis 2 dan 3 (data independen) adalah bukti generalisasi
  yang lebih kredibel, tapi tetap terbatas pada PHP (webshell) dan JavaScript (FPR produksi); belum
  ada data independen setara untuk Python atau Terraform.
- **CVE (OSV.dev), DNS/CT (crt.sh), dan Telegram tidak bisa diuji di lingkungan sandbox ini**
  (domain tersebut tidak ada di allowlist jaringan sandbox). Modulnya sudah diuji dengan tiruan
  (`node --test`, 27 kasus), tapi validasi dengan layanan sungguhan harus dijalankan di mesin
  dengan akses internet penuh (lihat §6).

## 6. Yang harus dijalankan sendiri (butuh internet penuh, tidak bisa dari sandbox ini)

```bash
# CVE nyata lewat OSV.dev — jalankan di folder berisi package-lock.json/requirements.txt sungguhan
node server.js . --once --json cve-hasil.json

# DNS, email, dan subdomain nyata milikmu
node server.js https://situsmu.com --saya-pemilik-situs --once --json dns-hasil.json

# Semgrep dengan ruleset registry penuh, sebagai pembanding yang lebih representatif
semgrep --config p/security-audit eval/corpus --json --output semgrep-registry.json
```

Simpan ketiga keluaran itu sebagai lampiran data pendukung naskah.

## 7. Cara mengulang semua angka di atas

```bash
npm install
npm test                                   # 27 unit test, semua modul
node eval/run-ours.mjs                     # Tabel 1, baris laba-laba-pemindai
/path/to/gitleaks detect --no-git --source eval/corpus --report-format json --report-path eval/results/gitleaks.json
semgrep --config eval/tools/semgrep-rules.yml --metrics off eval/corpus --json --output eval/results/semgrep.json
node eval/compare.mjs                      # Tabel 1 lengkap

git clone --depth 1 https://github.com/tennc/webshell.git /tmp/webshell-wild
node eval/run-wild.mjs /tmp/webshell-wild  # §3, recall korpus independen

git clone --depth 1 https://github.com/expressjs/express.git /tmp/benign-wild
node eval/run-benign.mjs /tmp/benign-wild/lib   # §3, FPR kode produksi
node eval/run-benign.mjs /tmp/benign-wild       # §3, FPR seluruh repo
```
