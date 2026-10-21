/* Pemeriksaan fungsional lebih dalam — stack fingerprint, sinyal auth, path berbahaya di HTML, dll.
   Semua tetap pasif (hanya membaca respons yang sudah di-GET). */

import { F } from './rules.js';

/** Deteksi stack dari header + cuplikan body. */
export function fingerprint(headers, body = '') {
  const h = headers;
  const bits = [];
  const xp = h.get('x-powered-by') || '';
  const srv = h.get('server') || '';
  const gen = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i.exec(body)?.[1]
    || /content=["']([^"']+)["'][^>]+name=["']generator["']/i.exec(body)?.[1] || '';

  if (/wordpress/i.test(body) || /wp-content|wp-includes/i.test(body)) bits.push('WordPress');
  if (/laravel/i.test(xp) || /laravel_session/i.test(h.get('set-cookie') || '')) bits.push('Laravel');
  if (/php/i.test(xp) || /\.php/i.test(body.slice(0, 2000))) bits.push('PHP');
  if (/express/i.test(xp)) bits.push('Express');
  if (/next\.js|__NEXT_DATA__/i.test(body)) bits.push('Next.js');
  if (/nuxt/i.test(body)) bits.push('Nuxt');
  if (/react/i.test(body) && /data-reactroot|__REACT/i.test(body)) bits.push('React');
  if (/joomla/i.test(gen) || /\/media\/jui\//i.test(body)) bits.push('Joomla');
  if (/drupal/i.test(gen) || /Drupal\.settings/i.test(body)) bits.push('Drupal');
  if (/cloudflare/i.test(srv) || h.get('cf-ray')) bits.push('Cloudflare');
  if (/nginx/i.test(srv)) bits.push('nginx');
  if (/apache/i.test(srv)) bits.push('Apache');
  if (/iis/i.test(srv)) bits.push('IIS');
  if (gen) bits.push(`generator:${gen.slice(0, 40)}`);

  return [...new Set(bits)];
}

/** Temuan berdasarkan stack yang terdeteksi (saran path yang sering lupa dilindungi). */
export function stackFindings(stack, body) {
  const f = [];
  if (stack.includes('WordPress')) {
    if (/wp-json\/wp\/v2\/users/i.test(body)) {
      /* probe terpisah sudah ada; di sini sinyal di HTML */
    }
    if (/<script[^>]+wp-emoji|window\._wpemojiSettings/i.test(body)) {
      // normal
    }
    // User enumeration via author archives sering aktif
    if (/author=\d+|\/author\/[a-z0-9-]+/i.test(body)) {
      f.push(F(0, 'stack-wp', 'WordPress: tautan author terdeteksi (sering dipakai enumerasi user)'));
    }
  }
  if (stack.includes('Laravel') && /APP_DEBUG\s*=\s*true|Whoops\\\\|facade\\\\Ignition/i.test(body)) {
    f.push(F(2, 'stack-laravel', 'Laravel: indikasi debug/Whoops terbaca di respons (jangan aktif di produksi)'));
  }
  return f;
}

/** Parameter berbahaya di URL internal yang terlihat di HTML (pasif). */
export function dangerousParamsInHtml(body, origin) {
  const f = [];
  const re = /(?:href|src|action)=["']([^"']*(?:\?|&)(?:file|path|page|include|doc|template|php_path|dir)=([^"'&#]+))/gi;
  let m;
  const hits = [];
  while ((m = re.exec(body)) && hits.length < 5) {
    const val = decodeURIComponent(m[2] || '');
    if (/\.\.|\/etc\/|php:\/\/|file:\/\/|data:\/\//i.test(val)) {
      hits.push(val.slice(0, 60));
    }
  }
  if (hits.length) {
    f.push(F(1, 'param-suspect', `Parameter path mencurigakan di HTML (indikasi LFI/path traversal): ${hits[0]}`));
  }
  return f;
}

/** Form yang POST ke domain luar (data bisa bocor ke pihak ketiga). */
export function externalFormActions($, origin) {
  const f = [];
  const bad = [];
  $('form[action]').each((_, el) => {
    try {
      const a = new URL(el.attribs.action || '', origin);
      if (a.origin !== origin && /^https?:$/.test(a.protocol)) bad.push(a.origin);
    } catch { /* */ }
  });
  if (bad.length) {
    f.push(F(1, 'form-external', `Form mengirim data ke domain luar: ${[...new Set(bad)].slice(0, 3).join(', ')}`));
  }
  return f;
}

/** Autocomplete pada field sensitif + input tersembunyi berlebih di form login. */
export function loginHardening($) {
  const f = [];
  const pw = $('input[type=password]');
  if (!pw.length) return f;
  const form = pw.closest('form');
  const hidden = form.find('input[type=hidden]').length;
  if (hidden > 12) {
    f.push(F(0, 'auth-hint', `Form login punya ${hidden} field hidden (wajar untuk framework; periksa apakah ada token yang lemah)`));
  }
  // Password field visible in query string patterns in action
  const act = form.attr('action') || '';
  if (/[?&](user|email|login)=/i.test(act)) {
    f.push(F(1, 'auth-hint', 'Action form login memuat parameter user di URL'));
  }
  return f;
}

/** Gabungan pemeriksaan dalam untuk satu respons HTML. */
export function deepHtmlChecks($, headers, body, origin) {
  const stack = fingerprint(headers, body);
  const f = [];
  if (stack.length) {
    f.push(F(0, 'stack', `Stack terdeteksi: ${stack.filter((s) => !s.startsWith('generator')).join(', ') || stack.join(', ')}`));
  }
  f.push(...stackFindings(stack, body));
  f.push(...dangerousParamsInHtml(body, origin));
  f.push(...externalFormActions($, origin));
  f.push(...loginHardening($));
  return { findings: f, stack };
}
