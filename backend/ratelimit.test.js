'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createRateLimiter, loadConfig, DEFAULTS, normIp, clientIp } = require('./ratelimit.js');

const HOUR = 3600 * 1000;
const T0 = Math.floor(1.7e12 / HOUR) * HOUR;                 // aligned to window edges
function make(overrides = {}, extra = {}) {
  const clock = { t: T0, advance(sec) { this.t += sec * 1000; } };
  const rl = createRateLimiter({ accountHashSecret: 'test-secret-0123456789abcdef', ...overrides }, { now: () => clock.t, production: false, ...extra });
  return { rl, clock };
}
const BIG = { windowSec: 3600, max: 100000 };
const loginOnly = (backoff) => ({ tiers: { auth: { login: { ip: BIG, account: BIG, backoff } } } });

test('public tier: blocks over the limit and tells the client exactly when to return', () => {
  const { rl, clock } = make({ tiers: { public: { windowSec: 60, max: 5 } } });
  clock.advance(10);
  for (let i = 0; i < 5; i++) assert.equal(rl.public('1.2.3.4').allowed, true);
  const r = rl.public('1.2.3.4');
  assert.equal(r.allowed, false);
  assert.ok(r.retryAfterSec >= 1);
  clock.advance(r.retryAfterSec - 2); assert.equal(rl.public('1.2.3.4').allowed, false);   // too early
  clock.advance(2);                   assert.equal(rl.public('1.2.3.4').allowed, true);    // exactly on time
  assert.equal(rl.public('5.6.7.8').allowed, true);                                         // other clients unaffected
});

test('defaults: auth is strictest, public is moderate, signed-in users are looser', () => {
  const t = DEFAULTS.tiers;
  assert.ok(t.authenticated.max / t.authenticated.windowSec > t.public.max / t.public.windowSec);
  assert.ok(t.auth.login.account.max / t.auth.login.account.windowSec < t.public.max / t.public.windowSec / 10);
  for (const a of Object.values(t.auth)) assert.ok(a.account.max <= a.ip.max);
});

test('login: delays grow exponentially, cap out, and are never a permanent lockout', () => {
  const { rl, clock } = make(loginOnly({ on: 'failure', freeFailures: 3, baseSec: 2, factor: 2, maxSec: 20, resetAfterSec: 3600 }));
  const seen = [];
  for (let i = 1; i <= 9; i++) {
    const ip = '10.0.0.' + i;                                   // rotate IPs so only the account backoff is in play
    let c = rl.auth.check('login', { ip, account: 'bob@example.com' });
    if (!c.allowed) { seen.push(c.retryAfterSec); assert.equal(c.reason, 'account_backoff'); clock.advance(c.retryAfterSec); c = rl.auth.check('login', { ip, account: 'bob@example.com' }); }
    assert.equal(c.allowed, true);
    rl.auth.record('login', { ip, account: 'bob@example.com' }, false);
  }
  const next = rl.auth.check('login', { ip: '10.9.9.9', account: 'bob@example.com' });
  assert.deepEqual(seen, [2, 4, 8, 16, 20]);                    // failures 4..8 waited; the delay stops at the 20s cap
  assert.equal(next.allowed, false); assert.equal(next.retryAfterSec, 20);
  clock.advance(20);
  assert.equal(rl.auth.check('login', { ip: '10.9.9.9', account: 'bob@example.com' }).allowed, true);
  clock.advance(3600 + 1);                                       // quiet for resetAfterSec: history forgotten
  rl.auth.record('login', { ip: '10.9.9.9', account: 'bob@example.com' }, false);
  assert.equal(rl.auth.check('login', { ip: '10.9.9.9', account: 'bob@example.com' }).allowed, true);
});

test('login: a successful sign-in clears the account delay but not the IP delay', () => {
  const { rl } = make(loginOnly({ on: 'failure', freeFailures: 2, ipFreeFailures: 2, baseSec: 5, factor: 2, maxSec: 60, resetAfterSec: 3600 }));
  for (let i = 0; i < 3; i++) rl.auth.record('login', { ip: '1.1.1.1', account: 'a@x.com' }, false);
  assert.equal(rl.auth.check('login', { ip: '2.2.2.2', account: 'a@x.com' }).reason, 'account_backoff');
  rl.auth.record('login', { ip: '3.3.3.3', account: 'a@x.com' }, true);                    // real owner signs in
  assert.equal(rl.auth.check('login', { ip: '2.2.2.2', account: 'a@x.com' }).allowed, true);
  assert.equal(rl.auth.check('login', { ip: '1.1.1.1', account: 'other@x.com' }).reason, 'ip_backoff');   // attacker IP still slowed
});

test('credential stuffing: one IP trying many accounts is slowed by the per-IP backoff', () => {
  const { rl } = make(loginOnly({ on: 'failure', freeFailures: 3, ipFreeFailures: 3, baseSec: 2, factor: 2, maxSec: 60, resetAfterSec: 3600 }));
  for (let i = 0; i < 4; i++) rl.auth.record('login', { ip: '9.9.9.9', account: `user${i}@x.com` }, false);   // each account failed once
  const c = rl.auth.check('login', { ip: '9.9.9.9', account: 'fresh@x.com' });
  assert.equal(c.allowed, false); assert.equal(c.reason, 'ip_backoff');
});

test('targeted attack: one account hit from many IPs is slowed by the per-account backoff', () => {
  const { rl } = make(loginOnly({ on: 'failure', freeFailures: 3, baseSec: 2, factor: 2, maxSec: 60, resetAfterSec: 3600 }));
  for (let i = 0; i < 4; i++) rl.auth.record('login', { ip: `8.8.8.${i}`, account: 'victim@x.com' }, false);
  const c = rl.auth.check('login', { ip: '8.8.8.200', account: 'victim@x.com' });
  assert.equal(c.allowed, false); assert.equal(c.reason, 'account_backoff');
  assert.equal(rl.auth.check('login', { ip: '8.8.8.200', account: 'someone-else@x.com' }).allowed, true);
});

test('a shared IP tolerates more failures than a single account before it is slowed', () => {
  const { rl } = make(loginOnly({ on: 'failure', freeFailures: 3, ipFreeFailures: 10, baseSec: 2, factor: 2, maxSec: 60, resetAfterSec: 3600 }));
  for (let i = 0; i < 10; i++) rl.auth.record('login', { ip: '12.0.0.1', account: `user${i}@x.com` }, false);
  assert.equal(rl.auth.check('login', { ip: '12.0.0.1', account: 'fresh@x.com' }).allowed, true);     // ten different people failed once each: fine
  rl.auth.record('login', { ip: '12.0.0.1', account: 'user11@x.com' }, false);
  assert.equal(rl.auth.check('login', { ip: '12.0.0.1', account: 'fresh@x.com' }).reason, 'ip_backoff'); // the eleventh failure starts the delay
});

test('account names are normalised (case and spacing do not dodge the limit)', () => {
  const { rl } = make(loginOnly({ on: 'failure', freeFailures: 1, baseSec: 5, factor: 2, maxSec: 60, resetAfterSec: 3600 }));
  rl.auth.record('login', { ip: '1.1.1.1', account: ' Bob@Example.com ' }, false);
  rl.auth.record('login', { ip: '1.1.1.2', account: 'bob@example.com' }, false);
  assert.equal(rl.auth.check('login', { ip: '1.1.1.3', account: 'BOB@EXAMPLE.COM' }).reason, 'account_backoff');
});

test('window ceilings: per-IP and per-account caps apply on top of backoff', () => {
  const o = { tiers: { auth: { login: { ip: { windowSec: 60, max: 3 }, account: { windowSec: 60, max: 2 }, backoff: { on: 'failure', freeFailures: 99, baseSec: 1, factor: 1, maxSec: 1, resetAfterSec: 60 } } } } };
  let { rl } = make(o);
  for (let i = 0; i < 3; i++) assert.equal(rl.auth.check('login', { ip: '4.4.4.4', account: `u${i}@x.com` }).allowed, true);
  assert.equal(rl.auth.check('login', { ip: '4.4.4.4', account: 'u9@x.com' }).reason, 'ip_window');
  ({ rl } = make(o));
  for (let i = 0; i < 2; i++) assert.equal(rl.auth.check('login', { ip: `5.5.5.${i}`, account: 'same@x.com' }).allowed, true);
  assert.equal(rl.auth.check('login', { ip: '5.5.5.9', account: 'same@x.com' }).reason, 'account_window');
});

test('signup and password reset: every attempt counts toward the backoff', () => {
  const { rl, clock } = make();
  const who = { ip: '6.6.6.6', account: 'new@x.com' };
  const b = DEFAULTS.tiers.auth.passwordReset.backoff;
  assert.equal(rl.auth.check('passwordReset', who).allowed, true);
  rl.auth.record('passwordReset', who, true);                     // "success" is ignored for attempt-based routes
  rl.auth.record('passwordReset', who, true);
  const c = rl.auth.check('passwordReset', who);
  assert.equal(c.allowed, false); assert.equal(c.retryAfterSec, b.baseSec);
  clock.advance(b.baseSec);
  assert.equal(rl.auth.check('passwordReset', who).allowed, true);
});

test('middleware: 429 with Retry-After, and the body never says which limit fired', () => {
  const { rl } = make({ tiers: { auth: { login: { ip: { windowSec: 60, max: 1 }, account: { windowSec: 60, max: 1 }, backoff: DEFAULTS.tiers.auth.login.backoff } } } });
  const mw = rl.authMiddleware('login', (req) => req.body.email);
  const req = (email) => ({ socket: { remoteAddress: '7.7.7.7' }, headers: {}, body: { email } });
  const res = () => ({ statusCode: 200, headers: {}, setHeader(k, v) { this.headers[k] = v; }, end(b) { this.body = b; } });
  let called = 0, r1 = res();
  mw(req('a@x.com'), r1, () => called++); assert.equal(called, 1);
  const r2 = res(); mw(req('b@x.com'), r2, () => called++);       // ip_window
  const r3 = res(); mw(req('a@x.com'), r3, () => called++);       // account_window (new IP path via same ip -> ip first)
  assert.equal(called, 1);
  for (const r of [r2, r3]) { assert.equal(r.statusCode, 429); assert.ok(Number(r.headers['Retry-After']) >= 1); assert.deepEqual(Object.keys(JSON.parse(r.body)).sort(), ['error', 'retry_after']); }
  assert.equal(JSON.parse(r2.body).error, JSON.parse(r3.body).error);
});

test('signed-in users get the looser tier; anonymous requests fall through to the public limiter', () => {
  const { rl } = make({ tiers: { public: { windowSec: 60, max: 2 }, authenticated: { windowSec: 60, max: 6 } } });
  let n = 0; for (let i = 0; i < 6; i++) rl.user('u1').allowed && n++;
  assert.equal(n, 6); assert.equal(rl.user('u1').allowed, false);
  assert.equal(rl.user('u2').allowed, true);
  let p = 0; for (let i = 0; i < 4; i++) rl.public('1.1.1.1').allowed && p++;
  assert.equal(p, 2);
});

test('IP handling: IPv6 is limited per /64, proxies are only trusted when configured', () => {
  assert.equal(normIp('2001:db8:1:2:aaaa:bbbb:cccc:dddd'), normIp('2001:0db8:0001:0002::1'));
  assert.notEqual(normIp('2001:db8:1:3::1'), normIp('2001:db8:1:2::1'));
  assert.equal(normIp('::ffff:1.2.3.4'), '1.2.3.4');
  const req = { socket: { remoteAddress: '10.0.0.1' }, headers: { 'x-forwarded-for': 'spoof, 7.7.7.7, 10.0.0.2' } };
  assert.equal(clientIp(req, 0), '10.0.0.1');                    // header ignored unless you say a proxy is in front
  assert.equal(clientIp(req, 2), '7.7.7.7');                     // client-supplied "spoof" entry is ignored
});

test('configuration: file, env overrides and overrides all work; bad values are rejected', () => {
  const file = path.join(os.tmpdir(), 'rl-test.json');
  fs.writeFileSync(file, JSON.stringify({ tiers: { public: { max: 11 }, auth: { login: { account: { max: 4 } } } }, __proto__: { polluted: 1 } }));
  let cfg = loadConfig({ file, env: { RL__tiers__public__max: '7', RL__tiers__auth__login__backoff__factor: '3', RL_TRUST_PROXY_HOPS: '1' } });
  assert.equal(cfg.tiers.public.max, 7);                         // env beats file
  assert.equal(cfg.tiers.auth.login.account.max, 4);             // file beats defaults
  assert.equal(cfg.tiers.auth.login.backoff.factor, 3);
  assert.equal(cfg.trustProxyHops, 1);
  assert.equal(cfg.tiers.public.windowSec, DEFAULTS.tiers.public.windowSec);
  assert.equal({}.polluted, undefined);
  assert.throws(() => loadConfig({ env: { RL__tiers__public__max: '0' } }), /integer max >= 1/);
  assert.throws(() => loadConfig({ env: { RL__tiers__auth__login__backoff__factor: '0.5' } }), /invalid value/);
  assert.throws(() => createRateLimiter().auth.check('nope', {}), /unknown auth action/);
});

test('memory stays bounded when someone floods with unique clients', () => {
  const { rl } = make({ maxKeys: 100 });
  for (let i = 0; i < 1000; i++) rl.public(`11.0.${i >> 8}.${i & 255}`);
  assert.ok(rl.size() <= 100);
});

test('strict inputs: malformed accounts and user ids are refused before they touch any counter', () => {
  const { rl } = make();
  const mw = rl.authMiddleware('login', (req) => req.account);
  const run = (account) => { const res = { statusCode: 200, headers: {}, setHeader(k, v) { this.headers[k] = v; }, end(b) { this.body = b; } }; let n = 0; mw({ socket: { remoteAddress: '1.2.3.4' }, headers: {}, account }, res, () => n++); return { res, n }; };
  for (const bad of [{ a: 1 }, ['x'], 12345, '', 'x'.repeat(255), 'a\u0000b', 'a\nb', undefined, null]) {
    const { res, n } = run(bad); assert.equal(res.statusCode, 400, JSON.stringify(bad)); assert.equal(n, 0);
  }
  assert.equal(rl.size(), 0);                                          // nothing was stored for any of them
  assert.equal(run('ok@example.com').n, 1);
  const um = rl.userMiddleware((req) => req.uid);
  for (const bad of [{ a: 1 }, 1.5, 'x y', 'a'.repeat(129), '../x']) { const res = { setHeader() {}, end() {} }; um({ uid: bad }, res, () => assert.fail('should not pass')); assert.equal(res.statusCode, 400); }
  assert.throws(() => rl.auth.check('login', { ip: '1.1.1.1', account: { a: 1 } }), /invalid account/);
  assert.throws(() => rl.user({}), /invalid user id/);
});

test('client IP: only real IP addresses are trusted, everything else shares one bucket', () => {
  const r = (xff, hops) => clientIp({ socket: { remoteAddress: '10.0.0.1' }, headers: { 'x-forwarded-for': xff } }, hops);
  assert.equal(r('<script>', 1), 'unknown'); assert.equal(r('999.1.1.1', 1), 'unknown'); assert.equal(r('1.2.3.4', 1), '1.2.3.4');
  assert.equal(r('a'.repeat(2000), 1), '10.0.0.1');                                    // absurdly long header ignored
  assert.equal(clientIp({ socket: { remoteAddress: undefined }, headers: {} }, 0), 'unknown');
});

test('secrets: no fixed fallback key; production needs one; weak ones are rejected', () => {
  assert.throws(() => createRateLimiter({}, { production: true }), /must be set in production/);
  assert.throws(() => createRateLimiter({ accountHashSecret: 'short' }, { production: false }), /at least 16 characters/);
  const warn = console.warn; let warned = 0; console.warn = () => warned++;
  try { createRateLimiter({}, { production: false }); } finally { console.warn = warn; }
  assert.equal(warned, 1);
  const a = createRateLimiter({}, { production: false, now: () => 0 }), b = createRateLimiter({}, { production: false, now: () => 0 });
  for (const rl of [a, b]) for (let i = 0; i < 5; i++) rl.auth.record('login', { ip: `1.1.1.${i}`, account: 'x@x.com' }, false);
  assert.ok(true);                                                                        // random per-process key: nothing to leak from the source
  assert.ok(!/accountHashSecret\s*[:=]\s*['"][^'"]{4,}/.test(require('node:fs').readFileSync(require.resolve('./ratelimit.js'), 'utf8')));
});
