/* Penjelasan temuan dalam bahasa plain — keunggulan untuk pemilik non-teknis.
   Setiap rule punya: mengapa berbahaya + dampak bisnis sederhana. */

const WHY = {
  csp: 'Tanpa CSP, situs lebih mudah disisipi skrip penipu (XSS). Pengunjung bisa kehilangan akun atau data.',
  'csp-weak': 'CSP yang longgar hampir sama dengan tidak ada CSP untuk serangan skrip.',
  xfo: 'Halaman bisa dipasang di iframe situs jahat (clickjacking) agar pengguna terkecoh klik.',
  hsts: 'Tanpa HSTS, pengguna bisa diarahkan ke versi HTTP dan disadap di Wi-Fi publik.',
  'cookie-secure': 'Cookie sesi bisa bocor lewat koneksi tidak terenkripsi.',
  'cookie-httponly': 'Skrip penipu di halaman bisa mencuri cookie login.',
  cors: 'Situs lain di internet bisa membaca respons API kamu dari browser pengguna.',
  'cors-cred': 'Kombinasi ini memungkinkan situs asing memakai sesi login pengunjungmu.',
  secret: 'Kunci yang bocor bisa dipakai orang lain mengakses layanan berbayar atau data.',
  exposed: 'File ini tidak boleh publik. Isinya sering berisi password atau konfigurasi.',
  'file-git': 'Seluruh riwayat kode dan kadang rahasia di commit lama bisa diunduh siapa saja.',
  drift: 'Perubahan domain skrip mendadak sering jadi tanda situs disisipi malware.',
  'open-redirect': 'Penyerang bisa membuat tautan seolah dari domainmu ke situs phishing.',
  'auth-hint': 'Penyerang bisa menebak email/username mana yang terdaftar lalu menargetkannya.',
  generator: 'Versi CMS yang terbaca memudahkan penyerang mencari exploit yang cocok.',
  sri: 'File dari CDN bisa diganti di perjalanan tanpa terdeteksi browser.',
  tls: 'Sertifikat bermasalah membuat koneksi tidak dipercaya dan rentan disadap.',
  'tls-chain': 'Browser menolak atau memperingatkan pengunjung — kepercayaan turun.',
  zap: 'Temuan dari mesin pemindai OWASP ZAP berdasarkan traffic dan payload uji.',
  securitytxt: 'Peneliti keamanan kesulitan melapor responsibel jika kontak tidak ada.',
  csrf: 'Tanpa token, pihak lain bisa memaksa browser pengguna mengirim aksi atas nama mereka.',
  mixed: 'Bagian halaman tidak terenkripsi meski alamatnya HTTPS.',
  errleak: 'Detail error membantu penyerang memahami struktur server dan database.',
  dirlist: 'Isi folder terlihat — memudahkan menemukan file cadangan atau konfigurasi.',
};

const BUSINESS = {
  2: 'Prioritas tinggi — perbaiki minggu ini. Risiko kebocoran data atau penyalahgunaan akun.',
  1: 'Prioritas sedang — jadwalkan perbaikan. Memperbesar permukaan serangan.',
  0: 'Prioritas rendah — rapikan saat ada waktu. Lebih ke kebersihan & best practice.',
};

export function explain(rule, lvl = 0) {
  return {
    mengapa: WHY[rule] || 'Temuan ini menandai konfigurasi atau pola yang tidak sesuai praktik keamanan umum.',
    dampak: BUSINESS[lvl] || BUSINESS[0],
  };
}

export function prioritize(findings) {
  // findings: [{ rule, lvl, text, path }]
  const crit = findings.filter((f) => f.lvl === 2);
  const med = findings.filter((f) => f.lvl === 1);
  const week = [];
  const seen = new Set();
  for (const f of [...crit, ...med]) {
    const k = f.rule;
    if (seen.has(k)) continue;
    seen.add(k);
    const ex = explain(f.rule, f.lvl);
    week.push({
      rule: f.rule,
      level: f.lvl === 2 ? 'kritis' : 'sedang',
      contoh: f.text.slice(0, 120),
      path: f.path,
      mengapa: ex.mengapa,
      aksi: f.fix || '',
    });
    if (week.length >= 8) break;
  }
  return week;
}
