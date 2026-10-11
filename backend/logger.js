'use strict';
/**
 * Server-side error log. Full detail (message, stack, context) goes HERE and never to the user.
 * - one JSON object per line, easy to search and ship to a log service
 * - secrets are redacted by key name (password, token, secret, key, authorization, cookie, ...)
 * - control characters are stripped from every string, so a visitor can't forge fake log lines
 * - long values are cut so a huge request can't fill the disk
 */
const SECRET_KEY = /pass(?:word|wd)?|pwd|secret|token|authorization|cookie|api[_-]?key|private|session|credential/i;
const MAX_STR = 2000, MAX_DEPTH = 4, MAX_KEYS = 40;

const MASKS = [   // secrets that appear inside free text (error messages, URLs) rather than under a key name
  [/\bBearer\s+[A-Za-z0-9._~+\/=-]+/gi, 'Bearer [redacted]'],
  [/(\b(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|authorization)\b["']?\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)/gi, '$1[redacted]'],
  [/(:\/\/[^\/\s:@]+:)[^\/\s@]+@/g, '$1[redacted]@'],
];
function cleanStr(s) {
  s = String(s).replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, ' ');
  for (const [rx, to] of MASKS) s = s.replace(rx, to);
  return s.length > MAX_STR ? s.slice(0, MAX_STR) + '…[cut]' : s;
}
function redact(v, depth = 0, seen = new WeakSet()) {
  if (v === null || v === undefined) return v;
  if (typeof v === 'string') return cleanStr(v);
  if (typeof v === 'number' || typeof v === 'boolean') return v;
  if (typeof v === 'bigint') return String(v);
  if (typeof v !== 'object' && typeof v !== 'function') return cleanStr(String(v));
  if (depth >= MAX_DEPTH || seen.has(v)) return '[…]';
  seen.add(v);
  if (Array.isArray(v)) return v.slice(0, MAX_KEYS).map((x) => redact(x, depth + 1, seen));
  const out = {};
  for (const k of Object.keys(v).slice(0, MAX_KEYS)) out[cleanStr(k)] = SECRET_KEY.test(k) ? '[redacted]' : redact(v[k], depth + 1, seen);
  return out;
}
function describeError(err) {
  if (err instanceof Error) {
    const o = { name: cleanStr(err.name), message: cleanStr(err.message), stack: cleanStr(err.stack || '') };
    if (err.code !== undefined) o.code = cleanStr(err.code);
    if (err.cause) o.cause = describeError(err.cause);
    return o;
  }
  return { name: 'NonError', message: cleanStr(typeof err === 'string' ? err : JSON.stringify(redact(err))) };
}
function createLogger(write = (line) => process.stderr.write(line + '\n'), now = () => new Date()) {
  const log = (level, msg, ctx) => {
    try { write(JSON.stringify({ time: now().toISOString(), level, msg: cleanStr(msg), ...(ctx ? { ctx: redact(ctx) } : {}) })); } catch { /* logging must never crash the app */ }
  };
  return {
    info: (msg, ctx) => log('info', msg, ctx),
    warn: (msg, ctx) => log('warn', msg, ctx),
    error: (msg, err, ctx) => {
      try { write(JSON.stringify({ time: now().toISOString(), level: 'error', msg: cleanStr(msg), error: describeError(err), ...(ctx ? { ctx: redact(ctx) } : {}) })); } catch { /* ignore */ }
    },
  };
}
module.exports = { createLogger, redact, cleanStr };
