/* Umpan serangan masuk: log auth SSH (mis. /var/log/auth.log) dan log honeypot Cowrie (JSON per baris).
   Hanya membaca berkas log. Sandi yang dicoba penyerang tidak pernah disimpan atau ditampilkan. */

import fs from 'node:fs';
import net from 'node:net';

const clean = (s, n = 80) => String(s ?? '').replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, '?').slice(0, n);

export function parseSshLine(line) {
  let m = /Failed (?:password|publickey|keyboard-interactive\/pam) for (?:invalid user )?(\S+) from (\S+) port \d+/.exec(line);
  if (m) return { kind: 'ssh', action: 'fail', user: clean(m[1], 32), ip: m[2] };
  m = /Invalid user (\S*) from (\S+)/.exec(line);
  if (m) return { kind: 'ssh', action: 'fail', user: clean(m[1] || '?', 32), ip: m[2] };
  m = /Accepted (\w+) for (\S+) from (\S+) port/.exec(line);
  if (m) return { kind: 'ssh', action: 'ok', user: clean(m[2], 32), ip: m[3] };
  return null;
}

export function parseCowrie(line) {
  let j;
  try { j = JSON.parse(line); } catch { return null; }
  const ip = j.src_ip;
  if (!ip) return null;
  switch (j.eventid) {
    case 'cowrie.login.failed': return { kind: 'honeypot', action: 'fail', user: clean(j.username, 32), ip };
    case 'cowrie.login.success': return { kind: 'honeypot', action: 'ok', user: clean(j.username, 32), ip };
    case 'cowrie.session.connect': return { kind: 'honeypot', action: 'connect', ip };
    case 'cowrie.command.input': return { kind: 'honeypot', action: 'command', cmd: clean(j.input, 100), ip };
    default: return null;
  }
}

export class IntelAggregator {
  constructor({ onEvent = () => {}, windowMs = 60000, threshold = 5, now = Date.now } = {}) {
    this.onEvent = onEvent;
    this.windowMs = windowMs;
    this.threshold = threshold;
    this.now = now;
    this.ips = new Map();
    this.total = { fail: 0, ok: 0 };
  }

  ingest(e, { backlog = false } = {}) {
    if (!e || !net.isIP(e.ip)) return;
    const t = this.now();
    let r = this.ips.get(e.ip);
    if (!r) {
      if (this.ips.size >= 2000) return;
      r = { ip: e.ip, fails: 0, oks: 0, users: new Set(), first: t, last: t, times: [], flaggedAt: 0, kinds: new Set() };
      this.ips.set(e.ip, r);
    }
    r.last = t;
    r.kinds.add(e.kind);
    if (e.user && r.users.size < 12) r.users.add(e.user);

    if (e.action === 'fail') {
      r.fails++;
      this.total.fail++;
      r.times.push(t);
      r.times = r.times.filter((x) => t - x <= this.windowMs).slice(-100);
      if (!backlog && r.times.length >= this.threshold && t - r.flaggedAt > 600000) {
        r.flaggedAt = t;
        this.onEvent({ type: 'brute', ip: e.ip, count: r.times.length, users: [...r.users].slice(0, 5), kind: e.kind });
      }
    } else if (e.action === 'ok') {
      r.oks++;
      this.total.ok++;
      if (!backlog && r.fails >= 3 && e.kind === 'ssh') this.onEvent({ type: 'success-after-fails', ip: e.ip, user: e.user, fails: r.fails });
    }
    if (!backlog && (e.action === 'command' || e.action === 'ok' || e.action === 'connect')) this.onEvent({ type: e.action, ip: e.ip, user: e.user, cmd: e.cmd, kind: e.kind });
  }

  top(n = 8) {
    return [...this.ips.values()]
      .filter((r) => r.fails > 0 || r.oks > 0)
      .sort((a, b) => b.fails - a.fails || b.last - a.last)
      .slice(0, n)
      .map((r) => ({ ip: r.ip, fails: r.fails, oks: r.oks, users: r.users.size, last: r.last, kinds: [...r.kinds] }));
  }
}

/** Membaca ekor berkas log. Mulai dari ~128 KB terakhir sebagai latar belakang (tanpa memicu peringatan). */
export function tailFile(file, onLine, { intervalMs = 3000, backlogBytes = 131072, onError = () => {} } = {}) {
  let offset = null;
  let partial = '';
  let stopped = false;

  async function poll() {
    if (stopped) return;
    try {
      const st = await fs.promises.stat(file);
      const first = offset === null;
      if (first) offset = Math.max(0, st.size - backlogBytes);
      if (st.size < offset) { offset = 0; partial = ''; } // log dirotasi
      if (st.size > offset) {
        const fh = await fs.promises.open(file, 'r');
        try {
          const len = Math.min(st.size - offset, 4 * 1024 * 1024);
          const buf = Buffer.alloc(len);
          const { bytesRead } = await fh.read(buf, 0, len, offset);
          offset += bytesRead;
          const lines = (partial + buf.subarray(0, bytesRead).toString('utf8')).split('\n');
          partial = lines.pop();
          for (const l of lines) onLine(l, { backlog: first });
        } finally {
          await fh.close();
        }
      }
    } catch (e) {
      onError(e);
    }
    if (!stopped) setTimeout(poll, intervalMs).unref?.();
  }
  poll();
  return { stop: () => { stopped = true; } };
}
