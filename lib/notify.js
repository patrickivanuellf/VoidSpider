/* Notifikasi ke Telegram (dan webhook opsional). Token dibaca dari environment dan tidak pernah dicetak.
   Hanya teks temuan yang dikirim. Nilai rahasia tidak pernah ada di teks temuan. */

const MARK = ['info', 'SEDANG', 'KRITIS'];

export function makeNotifier({ fetchImpl = fetch, env = process.env, label = '' } = {}) {
  const token = env.TELEGRAM_BOT_TOKEN;
  const chat = env.TELEGRAM_CHAT_ID;
  const hook = env.NOTIFY_WEBHOOK;
  const api = env.TELEGRAM_API || 'https://api.telegram.org';
  const min = Number(env.NOTIFY_MIN_LEVEL ?? 2);
  const enabled = Boolean((token && chat) || hook);
  const sent = new Set(); // dedup: satu temuan hanya diberitahukan sekali selama proses berjalan
  let firstDone = false;

  async function push(text) {
    const jobs = [];
    if (token && chat) {
      jobs.push(
        fetchImpl(`${api}/bot${token}/sendMessage`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ chat_id: chat, text: text.slice(0, 3900), disable_web_page_preview: true }),
          signal: AbortSignal.timeout(10000),
        }).catch(() => null)
      );
    }
    if (hook) {
      jobs.push(
        fetchImpl(hook, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ text, label }),
          signal: AbortSignal.timeout(10000),
        }).catch(() => null)
      );
    }
    await Promise.all(jobs);
  }

  /** items: [{ path, f }], summary: ringkasan siklus. Siklus pertama hanya mengirim satu ringkasan. */
  async function cycle(items, summary) {
    if (!enabled) return { sent: 0 };
    const worth = items.filter(({ f }) => f.lvl >= min);
    if (!firstDone) {
      firstDone = true;
      worth.forEach(({ path, f }) => sent.add(`${path}|${f.rule}|${f.text}`));
      await push(`Pemindaian pertama selesai untuk ${label}\nSkor ${summary.skor}/100 (${summary.nilai}) · ${summary.kritis} kritis, ${summary.sedang} sedang, ${summary.info} info.\nSelanjutnya hanya temuan baru yang dikirim.`);
      return { sent: 1 };
    }
    const fresh = worth.filter(({ path, f }) => !sent.has(`${path}|${f.rule}|${f.text}`));
    fresh.forEach(({ path, f }) => sent.add(`${path}|${f.rule}|${f.text}`));
    if (!fresh.length) return { sent: 0 };
    const lines = fresh.slice(0, 10).map(({ path, f }) => `[${MARK[f.lvl]}] ${path}: ${f.text}`);
    const more = fresh.length > 10 ? `\n...dan ${fresh.length - 10} temuan baru lainnya` : '';
    await push(`Temuan baru di ${label} (skor ${summary.skor}/100, ${summary.nilai})\n${lines.join('\n')}${more}`);
    return { sent: 1 };
  }

  /** Peringatan satu kali untuk kejadian langsung (mis. brute force SSH). */
  async function alert(key, text) {
    if (!enabled || sent.has(key)) return false;
    sent.add(key);
    await push(text);
    return true;
  }

  return { enabled, cycle, alert };
}
