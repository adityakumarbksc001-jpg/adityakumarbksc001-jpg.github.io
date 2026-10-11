'use strict';
/**
 * Tiered rate limiting with no dependencies.
 *   - public endpoints:        moderate limit per client IP
 *   - authenticated actions:   looser limit per signed-in user
 *   - auth routes (login, signup, password reset): strict limits per IP AND per account,
 *     plus exponential backoff (growing delays, capped, decaying) instead of a hard lockout.
 * Every threshold lives in the config (DEFAULTS < JSON file < RL__ env vars < overrides).
 * The default store is in memory (per process). For several servers, swap it for Redis or an edge limiter.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const { NOCTRL } = require('./validate.js');

const DEFAULTS = {
  trustProxyHops: 0,        // reverse proxies in front of the app (0 = use the socket address)
  accountHashSecret: '',    // HMAC key for account identifiers; set RL_ACCOUNT_HASH_SECRET (16+ characters). Never put it in git.
  maxKeys: 100000,          // memory bound for the in-memory store
  tiers: {
    public:        { windowSec: 60, max: 60 },     // per IP
    authenticated: { windowSec: 60, max: 300 },    // per user id
    auth: {
      login: {
        ip:      { windowSec: 900, max: 30 },
        account: { windowSec: 900, max: 10 },
        backoff: { on: 'failure', freeFailures: 3, ipFreeFailures: 10, baseSec: 2, factor: 2, maxSec: 900, resetAfterSec: 3600 },
      },
      signup: {
        ip:      { windowSec: 3600, max: 10 },
        account: { windowSec: 3600, max: 3 },
        backoff: { on: 'attempt', freeFailures: 2, ipFreeFailures: 6, baseSec: 30, factor: 2, maxSec: 3600, resetAfterSec: 7200 },
      },
      passwordReset: {
        ip:      { windowSec: 3600, max: 10 },
        account: { windowSec: 3600, max: 3 },
        backoff: { on: 'attempt', freeFailures: 1, ipFreeFailures: 5, baseSec: 60, factor: 2, maxSec: 3600, resetAfterSec: 7200 },
      },
    },
  },
};

/* ---------------- configuration ---------------- */
const BAD = new Set(['__proto__', 'constructor', 'prototype']);
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
function deepMerge(a, b) {
  if (!isObj(b)) return b === undefined ? a : b;
  const out = { ...a };
  for (const k of Object.keys(b)) {
    if (BAD.has(k)) continue;
    out[k] = isObj(a && a[k]) && isObj(b[k]) ? deepMerge(a[k], b[k]) : b[k];
  }
  return out;
}
function envTree(env, prefix) {     // PREFIX__a__b=5  ->  { a: { b: 5 } }
  const out = {};
  for (const [key, raw] of Object.entries(env || {})) {
    if (!key.startsWith(prefix)) continue;
    const path = key.slice(prefix.length).split('__');
    if (path.some((p) => !p || BAD.has(p))) continue;
    let v = raw;
    if (/^-?\d+(\.\d+)?$/.test(raw)) v = Number(raw); else if (raw === 'true') v = true; else if (raw === 'false') v = false;
    let o = out;
    path.slice(0, -1).forEach((p) => { if (!isObj(o[p])) o[p] = {}; o = o[p]; });
    o[path[path.length - 1]] = v;
  }
  return out;
}
function fromEnv(env) {
  const out = envTree(env, 'RL__');
  if (env && env.RL_ACCOUNT_HASH_SECRET) out.accountHashSecret = env.RL_ACCOUNT_HASH_SECRET;
  if (env && env.RL_TRUST_PROXY_HOPS !== undefined) out.trustProxyHops = Number(env.RL_TRUST_PROXY_HOPS);
  return out;
}
function checkWindow(w, name) {
  if (!isObj(w) || !Number.isFinite(w.windowSec) || w.windowSec <= 0 || !Number.isInteger(w.max) || w.max < 1)
    throw new Error(`rate-limit config: ${name} needs windowSec > 0 and an integer max >= 1`);
}
function validate(cfg) {
  if (!Number.isInteger(cfg.trustProxyHops) || cfg.trustProxyHops < 0) throw new Error('rate-limit config: trustProxyHops must be an integer >= 0');
  if (cfg.accountHashSecret !== '' && (typeof cfg.accountHashSecret !== 'string' || cfg.accountHashSecret.length < 16)) throw new Error('rate-limit config: accountHashSecret must be at least 16 characters');
  if (!Number.isInteger(cfg.maxKeys) || cfg.maxKeys < 100) throw new Error('rate-limit config: maxKeys must be an integer >= 100');
  checkWindow(cfg.tiers.public, 'tiers.public');
  checkWindow(cfg.tiers.authenticated, 'tiers.authenticated');
  for (const [name, a] of Object.entries(cfg.tiers.auth)) {
    checkWindow(a.ip, `tiers.auth.${name}.ip`);
    checkWindow(a.account, `tiers.auth.${name}.account`);
    const b = a.backoff;
    if (!isObj(b) || !['failure', 'attempt'].includes(b.on)) throw new Error(`rate-limit config: tiers.auth.${name}.backoff.on must be "failure" or "attempt"`);
    if (b.ipFreeFailures !== undefined && !(b.ipFreeFailures >= 0)) throw new Error(`rate-limit config: tiers.auth.${name}.backoff.ipFreeFailures must be >= 0`);
    if (!(b.freeFailures >= 0) || !(b.baseSec > 0) || !(b.factor >= 1) || !(b.maxSec >= b.baseSec) || !(b.resetAfterSec > 0))
      throw new Error(`rate-limit config: tiers.auth.${name}.backoff has an invalid value`);
  }
  return cfg;
}
function loadConfig({ file, env = process.env, overrides } = {}) {
  let cfg = DEFAULTS;
  const f = file || (env && env.RL_CONFIG);
  if (f) cfg = deepMerge(cfg, JSON.parse(fs.readFileSync(f, 'utf8')));
  cfg = deepMerge(cfg, fromEnv(env));
  cfg = deepMerge(cfg, overrides || {});
  return validate(cfg);
}

/* ---------------- identifiers ---------------- */
function normIp(ip) {
  ip = String(ip || 'unknown').trim().toLowerCase();
  const m = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (m) return m[1];
  if (ip.includes('%')) ip = ip.split('%')[0];
  if (!ip.includes(':')) return ip;                 // IPv4 or unknown
  const [h, t] = ip.split('::');                    // IPv6: limit per /64 so rotating addresses doesn't help
  const head = h ? h.split(':') : [];
  const tail = ip.includes('::') && t ? t.split(':') : [];
  const fill = ip.includes('::') ? Math.max(0, 8 - head.length - tail.length) : 0;
  return head.concat(Array(fill).fill('0'), tail).slice(0, 4).map((x) => (x || '0').replace(/^0+(?=.)/, '')).join(':') + '::/64';
}
function clientIp(req, hops = 0) {
  const sock = req.socket && req.socket.remoteAddress;
  let ip = sock;
  if (hops) {
    const raw = String(req.headers && req.headers['x-forwarded-for'] || '');
    if (raw.length <= 1000) {
      const xff = raw.split(',').map((s) => s.trim()).filter(Boolean);
      ip = xff[xff.length - hops] || sock;
    }
  }
  return typeof ip === 'string' && net.isIP(ip) ? ip : 'unknown';        // anything that is not a real IP address goes to one shared bucket
}
const accountErr = (a) => a == null ? '' : (typeof a !== 'string' || a.length < 1 || a.length > 254 || NOCTRL.test(a)) ? 'invalid account identifier' : '';
const userIdOk = (u) => (typeof u === 'string' || Number.isSafeInteger(u)) && /^[A-Za-z0-9_.:@-]{1,128}$/.test(String(u));

/* ---------------- limiter ---------------- */
function createRateLimiter(config = {}, opts = {}) {
  const cfg = validate(deepMerge(DEFAULTS, config));
  const production = opts.production !== undefined ? opts.production : process.env.NODE_ENV === 'production';
  if (!cfg.accountHashSecret && production) throw new Error('RL_ACCOUNT_HASH_SECRET must be set in production');
  if (!cfg.accountHashSecret) console.warn('rate-limit: RL_ACCOUNT_HASH_SECRET is not set; using a random key that changes on every restart');
  const secret = cfg.accountHashSecret || crypto.randomBytes(32).toString('hex');
  const clock = opts.now || Date.now;
  const onBlock = opts.onBlock || (() => {});
  const store = new Map();   // key -> entry (Map order = least recently used first)
  let ops = 0;

  function sweep(now) { for (const [k, e] of store) if (e.exp <= now) store.delete(k); }
  function touch(key, make, ttlMs, now) {
    let e = store.get(key);
    if (e && e.exp <= now) { store.delete(key); e = undefined; }
    if (e) store.delete(key); else e = make();
    e.exp = now + ttlMs; store.set(key, e);
    while (store.size > cfg.maxKeys) store.delete(store.keys().next().value);
    if (++ops % 500 === 0) sweep(now);
    return e;
  }
  const acctKey = (a) => crypto.createHmac('sha256', secret)
    .update(String(a).normalize('NFKC').trim().toLowerCase().slice(0, 254)).digest('hex').slice(0, 32);

  /* sliding-window counter: current bucket + weighted previous bucket */
  function win(key, w, now) {
    const ms = w.windowSec * 1000, idx = Math.floor(now / ms);
    const e = touch('w:' + key, () => ({ idx, cur: 0, prev: 0 }), ms * 2, now);
    if (e.idx !== idx) { e.prev = e.idx === idx - 1 ? e.cur : 0; e.cur = 0; e.idx = idx; }
    return { e, ms, est: e.cur + e.prev * (1 - (now % ms) / ms) };
  }
  function waitFor(e, max, ms, now) {   // seconds until one more request would fit
    const pos = now % ms;
    if (e.prev > 0) {
      const need = max - 1 - e.cur;
      if (need >= 0) { const f = 1 - need / e.prev; if (f <= 1) return Math.max(1, Math.ceil((Math.max(0, f * ms - pos)) / 1000)); }
    }
    const f = e.cur > 0 ? Math.max(0, 1 - (max - 1) / e.cur) : 0;
    return Math.max(1, Math.ceil(((ms - pos) + f * ms) / 1000));
  }
  function winCheck(key, w, now) {
    const { e, ms, est } = win(key, w, now);
    const ok = est + 1 <= w.max;
    return { ok, limit: w.max, remaining: Math.max(0, Math.floor(w.max - est - (ok ? 1 : 0))),
             retryAfterSec: ok ? 0 : waitFor(e, w.max, ms, now), resetSec: Math.ceil((ms - (now % ms)) / 1000) };
  }
  const winHit = (key, w, now) => { win(key, w, now).e.cur++; };

  /* exponential backoff: free failures, then base * factor^n, capped at maxSec, forgotten after resetAfterSec */
  function boWait(key, b, now) {
    const e = store.get('b:' + key);
    if (!e) return 0;
    if (now - e.last > b.resetAfterSec * 1000) { store.delete('b:' + key); return 0; }
    return Math.max(0, e.next - now);
  }
  function boFail(key, b, now, isIp) {
    const e = touch('b:' + key, () => ({ fails: 0, last: 0, next: 0 }), b.resetAfterSec * 1000, now);
    if (e.last && now - e.last > b.resetAfterSec * 1000) e.fails = 0;
    e.fails++; e.last = now;
    const over = e.fails - (isIp && b.ipFreeFailures !== undefined ? b.ipFreeFailures : b.freeFailures);   // a shared IP tolerates more failures than one account
    e.next = over > 0 ? now + Math.min(b.maxSec, b.baseSec * Math.pow(b.factor, over - 1)) * 1000 : 0;
  }

  const simple = (prefix, id, w) => {
    const now = clock(), key = prefix + id, c = winCheck(key, w, now);
    if (c.ok) winHit(key, w, now); else onBlock({ tier: prefix, key: id, retryAfterSec: c.retryAfterSec });
    return { allowed: c.ok, limit: c.limit, remaining: c.remaining, retryAfterSec: c.retryAfterSec, resetSec: c.resetSec };
  };

  const auth = {
    check(action, { ip, account } = {}) {
      const a = cfg.tiers.auth[action];
      if (!a) throw new Error(`unknown auth action "${action}"`);
      if (accountErr(account)) throw new TypeError(accountErr(account));
      const now = clock(), ipk = `${action}:ip:${normIp(ip)}`, ack = account != null && String(account).trim() ? `${action}:acct:${acctKey(account)}` : null;
      const deny = (reason, sec) => { onBlock({ tier: 'auth', action, reason, retryAfterSec: sec }); return { allowed: false, reason, retryAfterSec: Math.max(1, sec) }; };
      let d = boWait(ipk, a.backoff, now);                 if (d > 0) return deny('ip_backoff', Math.ceil(d / 1000));
      if (ack) { d = boWait(ack, a.backoff, now);          if (d > 0) return deny('account_backoff', Math.ceil(d / 1000)); }
      const wi = winCheck(ipk, a.ip, now);                 if (!wi.ok) return deny('ip_window', wi.retryAfterSec);
      if (ack) { const wa = winCheck(ack, a.account, now); if (!wa.ok) return deny('account_window', wa.retryAfterSec); }
      winHit(ipk, a.ip, now); if (ack) winHit(ack, a.account, now);
      return { allowed: true };
    },
    /** Call after the attempt. login: record(ok). signup / passwordReset ("attempt"): every call counts. */
    record(action, { ip, account } = {}, ok = false) {
      const a = cfg.tiers.auth[action];
      if (!a) throw new Error(`unknown auth action "${action}"`);
      if (accountErr(account)) throw new TypeError(accountErr(account));
      const now = clock(), ipk = `${action}:ip:${normIp(ip)}`, ack = account != null && String(account).trim() ? `${action}:acct:${acctKey(account)}` : null;
      if (a.backoff.on === 'failure' && ok) { if (ack) store.delete('b:' + ack); return; }   // success clears the account only; the IP keeps its history
      boFail(ipk, a.backoff, now, true);
      if (ack) boFail(ack, a.backoff, now, false);
    },
  };

  /* ---- plain Node / Express style middleware ---- */
  function deny429(res, r) {
    res.statusCode = 429;
    res.setHeader('Retry-After', String(r.retryAfterSec));
    if (r.limit !== undefined) { res.setHeader('RateLimit-Limit', String(r.limit)); res.setHeader('RateLimit-Remaining', '0'); res.setHeader('RateLimit-Reset', String(r.retryAfterSec)); }
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'too_many_requests', retry_after: r.retryAfterSec }));   // same message for every cause
  }
  function reject400(res) { res.statusCode = 400; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ error: 'invalid_request' })); }
  function pass(res, r) { res.setHeader('RateLimit-Limit', String(r.limit)); res.setHeader('RateLimit-Remaining', String(r.remaining)); res.setHeader('RateLimit-Reset', String(r.resetSec)); }

  return {
    config: cfg,
    public: (ip) => simple('pub:', normIp(ip), cfg.tiers.public),
    user: (userId) => { if (!userIdOk(userId)) throw new TypeError('invalid user id'); return simple('usr:', String(userId), cfg.tiers.authenticated); },
    auth,
    publicMiddleware() {
      return (req, res, next) => { const r = this.public(clientIp(req, cfg.trustProxyHops)); if (!r.allowed) return deny429(res, r); pass(res, r); next(); };
    },
    userMiddleware(getUserId) {
      return (req, res, next) => {
        const id = getUserId(req);
        if (id == null) return next();   // not signed in: the public limiter applies instead
        if (!userIdOk(id)) return reject400(res);
        const r = this.user(id); if (!r.allowed) return deny429(res, r); pass(res, r); next();
      };
    },
    /** getAccount(req) -> the email / username being tried. Adds req.rateLimit.succeed() / .fail(). */
    authMiddleware(action, getAccount) {
      return (req, res, next) => {
        const ip = clientIp(req, cfg.trustProxyHops), account = getAccount(req);
        if (accountErr(account) || account == null) return reject400(res);   // malformed account: refused before it touches any counter
        const r = auth.check(action, { ip, account });
        if (!r.allowed) return deny429(res, r);
        if (cfg.tiers.auth[action].backoff.on === 'attempt') auth.record(action, { ip, account }, false);
        req.rateLimit = { succeed: () => auth.record(action, { ip, account }, true), fail: () => auth.record(action, { ip, account }, false) };
        next();
      };
    },
    size: () => store.size,
  };
}

module.exports = { createRateLimiter, loadConfig, DEFAULTS, normIp, clientIp, deepMerge, envTree };
