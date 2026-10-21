<div align="center">

# Laba-laba Pemindai

**Audit keamanan yang bisa dilihat, dipahami, dan diperbaiki.**

Pemindai keamanan untuk situs web dan berkas lokal milik sendiri, dengan dasbor graf realtime,\
deteksi secret, deteksi malware berbasis aturan dan ML, serta integrasi opsional OWASP ZAP.

![Versi](https://img.shields.io/badge/versi-9.6.0-0b7285?style=flat-square)
![Node.js](https://img.shields.io/badge/node-%E2%89%A5%2018.14-339933?style=flat-square&logo=node.js&logoColor=white)
![Mode](https://img.shields.io/badge/mode-situs%20%7C%20berkas-495057?style=flat-square)
![Audit](https://img.shields.io/badge/audit-pasif%20%26%20non--destruktif-2b8a3e?style=flat-square)
![ZAP](https://img.shields.io/badge/OWASP%20ZAP-opsional-1c7ed6?style=flat-square)

<!-- Ganti dengan screenshot atau GIF dasbor -->
<!-- <img src="docs/dasbor.png" alt="Dasbor Laba-laba Pemindai" width="860"> -->

</div>

> [!IMPORTANT]
> Gunakan hanya pada aset yang kamu miliki atau yang sudah memberi izin tertulis.
> Flag `--saya-pemilik-situs` wajib untuk target di luar localhost.

---

## Daftar Isi

- [Fitur Utama](#fitur-utama)
- [Persyaratan dan Instalasi](#persyaratan-dan-instalasi)
- [Menjalankan](#menjalankan)
- [Integrasi OWASP ZAP](#integrasi-owasp-zap)
- [Flag CLI](#flag-cli)
- [Variabel Lingkungan](#variabel-lingkungan)
- [Dasbor dan Laporan](#dasbor-dan-laporan)
- [Skor](#skor)
- [Arsitektur](#arsitektur)
- [Cakupan: Dilakukan dan Tidak](#cakupan-dilakukan-dan-tidak)
- [Evaluasi dan Penelitian](#evaluasi-dan-penelitian)
- [Etika dan Hukum](#etika-dan-hukum)
- [Lisensi](#lisensi)

---

## Fitur Utama

| Area | Kemampuan |
| --- | --- |
| **Crawler** | Merayapi halaman dan tautan, divisualisasikan sebagai node realtime |
| **Header dan cookie** | CSP, HSTS, X-Frame-Options, CORS berbahaya, flag `Secure` / `HttpOnly` / `SameSite` |
| **Probe path** | `.env`, `.git`, Adminer, phpMyAdmin, backup SQL, log Laravel, dan lainnya. Isi respons divalidasi agar tidak salah deteksi |
| **Secret** | AWS, GitHub, Stripe, Midtrans, Xendit, Telegram, Discord, private key, connection string |
| **Fingerprint stack** | WordPress, Laravel, PHP, Next.js, nginx, Cloudflare, dan lainnya |
| **Open redirect** | Parameter `redirect`, `next`, `returnUrl` yang mengarah ke domain luar |
| **Safe signals** | Sinyal XSS reflection dan SQL error yang **non-destruktif** (bukan exploit) |
| **Drift baseline** | Mendeteksi domain skrip baru. CDN umum seperti Google tidak dianggap kritis |
| **OWASP ZAP** | Spider dan passive scan. Active scan opsional dengan konfirmasi risiko |
| **Mode berkas** | Secret, webshell (aturan bergaya YARA), malware ML, analisis taint, Infrastructure as Code |
| **Laporan** | JSON, Markdown, dan ringkasan pimpinan (`/report-pimpinan.md`) |

---

## Persyaratan dan Instalasi

- **Node.js** 18.14 atau lebih baru
- **OWASP ZAP** 2.x (opsional, hanya jika memakai `--zap`)

```bash
git clone https://github.com/<username>/laba-laba-pemindai.git
cd laba-laba-pemindai
npm install
```

---

## Menjalankan

### Mode situs

```bash
node server.js https://situsmu.com --saya-pemilik-situs
```

Preset kecepatan untuk situs yang lambat, misalnya situs kampus:

```bash
node server.js https://situsmu.com --saya-pemilik-situs --profil kampus
```

### Mode berkas lokal

```bash
node server.js ./folder-proyek
node server.js ./folder-proyek --once --offline
```

Latih ulang model ML malware:

```bash
npm run train-ml
```

Setelah server berjalan, buka dasbor di **http://127.0.0.1:3000**.

---

## Integrasi OWASP ZAP

ZAP dijalankan sendiri sebagai daemon. Laba-laba hanya memanggil REST API-nya.

**1. Jalankan daemon ZAP**

```bash
/path/ke/zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.disablekey=true
```

**2. Spider dan passive scan**

```bash
node server.js https://situsmu.com --saya-pemilik-situs --zap http://127.0.0.1:8080
```

Jika ZAP sudah punya data, lewati spider:

```bash
node server.js https://situsmu.com --saya-pemilik-situs \
  --zap http://127.0.0.1:8080 --zap-skip-spider
```

**3. Active scan** (hanya staging atau milik sendiri)

```bash
node server.js https://situsmu.com \
  --saya-pemilik-situs \
  --zap http://127.0.0.1:8080 \
  --zap-active-scan \
  --saya-paham-risiko-active-scan
```

> [!WARNING]
> Active scan mengirim payload serangan sungguhan. Jalankan ke staging, bukan produksi yang sedang dipakai. Kedua flag (`--zap-active-scan` dan `--saya-paham-risiko-active-scan`) wajib dipasang bersamaan.

---

## Flag CLI

| Flag | Fungsi |
| --- | --- |
| `--saya-pemilik-situs` | Wajib untuk URL publik (klaim kepemilikan atau izin) |
| `--zap URL` | Hubungkan ke daemon ZAP |
| `--zap-api-key K` | API key ZAP, jika diaktifkan |
| `--zap-skip-spider` | Jangan jalankan spider ZAP, pakai data yang sudah ada |
| `--zap-active-scan` | Active scan ZAP (butuh `--saya-paham-risiko-active-scan`) |
| `--profil kampus\|umkm\|wordpress\|ketat` | Preset interval, concurrency, dan batas halaman |
| `--terima-perubahan` | Terima drift baseline (domain atau berkas baru) |
| `--once` | Satu siklus lalu keluar, cocok untuk CI |
| `--offline` | Lewati DNS dan CVE eksternal |
| `--json PATH` / `--md PATH` | Tulis laporan ke berkas |
| `--cookie` / `--header` | Audit terautentikasi sebagai akun uji milikmu sendiri |

---

## Variabel Lingkungan

| Variabel | Bawaan | Fungsi |
| --- | --- | --- |
| `PORT` | `3000` | Port dasbor |
| `BIND` | `127.0.0.1` | Alamat yang didengarkan |
| `INTERVAL` | `90` (situs) / `30` (berkas) | Jeda antar siklus, dalam detik |
| `CONCURRENCY` | `2` / `3` | Jumlah kaki crawler paralel |
| `MAX_PAGES` | `200` / `400` | Batas jumlah node |
| `DELAY_MS` | `280` / `30` | Jeda antar permintaan |
| `TIMEOUT_MS` | `10000` | Batas waktu tiap permintaan |

Contoh:

```bash
INTERVAL=300 CONCURRENCY=2 node server.js https://situsmu.com --saya-pemilik-situs
```

---

## Dasbor dan Laporan

Dasbor menampilkan graf realtime dari halaman dan berkas yang sedang dipindai.

- Seret node untuk memindahkan, scroll untuk zoom
- Klik dua kali pada latar untuk mereset kamera
- Tombol **JSON** dan **MARKDOWN** untuk mengunduh laporan
- Laporan untuk pimpinan: `http://127.0.0.1:3000/report-pimpinan.md`

Setiap temuan disertai penjelasan dengan bahasa awam dan aksi yang disarankan untuk minggu ini.

---

## Skor

Temuan dibagi menjadi tiga tingkat: **info**, **sedang**, dan **kritis**. Skor 0 sampai 100 (nilai A sampai F) dihitung dari temuan unik. Temuan kritis berbobot lebih berat, dengan penurunan yang melandai agar situs besar tidak otomatis bernilai nol.

---

## Arsitektur

```text
server.js            HTTP + SSE dasbor + siklus pindai
lib/rules.js         Temuan F(), PROBES, SECRETS, CODE_RULES
lib/zap.js           Klien REST ZAP (spider sekali, active scan aman-gagal)
lib/drift.js         Baseline dan whitelist CDN
lib/deepcheck.js     Fingerprint stack, form eksternal, parameter mencurigakan
lib/safe_signals.js  Sinyal XSS/SQL non-destruktif
lib/malware.js       Aturan webshell dan backdoor
lib/ml_malware.js    Klasifikasi fitur + regresi logistik
lib/filescan.js      Mode folder dan berkas
lib/explain.js       Penjelasan bahasa awam + aksi minggu ini
public/              Dasbor graf
eval/                Corpus, skrip evaluasi, dan pelatihan ML
```

---

## Cakupan: Dilakukan dan Tidak

| Dilakukan | Tidak dilakukan |
| --- | --- |
| Audit pasif dan sinyal non-destruktif | RCE otomatis, dump database |
| Active scan ZAP (opsional, berizin) | Pengambilalihan akun atau brute force |
| Deteksi secret dan webshell | Eksploitasi sistem pihak ketiga |
| Laporan dan saran perbaikan | Menyimpan password di log |

---

## Evaluasi dan Penelitian

```bash
npm test          # unit test
npm run eval      # bandingkan deteksi terhadap corpus
npm run train-ml  # latih model ml-malware dari eval/corpus
```

- Corpus ada di `eval/corpus/` (secrets, webshell, taint, jwt, iac)
- Model ML tersimpan di `eval/results/ml-malware-model.json`
- Untuk naskah atau skripsi: dokumentasikan batasan etika, ukur precision dan recall pada corpus, lalu bandingkan aturan YARA dengan ML

---

## Etika dan Hukum

1. Hanya untuk target milik sendiri atau yang berizin tertulis.
2. Utamakan staging untuk active scan.
3. Hormati rate limit dan jangan membebani produksi.
4. Jangan pakai alat ini untuk menyerang sistem orang lain.

Penyalahgunaan sepenuhnya menjadi tanggung jawab pengguna.

---

## Lisensi

Proyek pribadi dan penelitian. Status lisensi mengikuti `package.json` (`UNLICENSED` kecuali diubah).

---

## Kredit

- OWASP ZAP sebagai mesin spider dan scan opsional
- Dibangun untuk konteks audit aset Indonesia: bahasa, gateway pembayaran seperti Midtrans dan Xendit, serta profil kampus dan UMKM

<div align="center">

**Laba-laba Pemindai**: audit yang bisa dilihat, dipahami, dan diperbaiki.

</div>
