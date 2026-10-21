/* Mengenali WAF/CDN dari header respons. Informasional saja: membantu menjelaskan kalau banyak
   halaman diblokir, hasil audit bisa tidak lengkap bukan berarti situsnya sudah aman total. */

const SIGNATURES = [
  { name: 'Cloudflare', test: (h) => h.has('cf-ray') || /cloudflare/i.test(h.get('server') || '') },
  { name: 'Sucuri', test: (h) => h.has('x-sucuri-id') || h.has('x-sucuri-cache') },
  { name: 'Akamai', test: (h) => /akamaighost/i.test(h.get('server') || '') || h.has('x-akamai-transformed') },
  { name: 'Imperva/Incapsula', test: (h) => h.has('x-iinfo') || /incap_ses|visid_incap/i.test(h.get('set-cookie') || '') },
  { name: 'AWS WAF/ELB', test: (h) => /AWSALB|awselb/i.test(h.get('set-cookie') || '') },
  { name: 'Fastly', test: (h) => h.has('fastly-debug-digest') || /fastly/i.test(h.get('x-served-by') || '') },
];

export function detectWaf(headers) {
  for (const s of SIGNATURES) {
    try { if (s.test(headers)) return s.name; } catch { /* abaikan */ }
  }
  return null;
}
