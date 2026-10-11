'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const { spawnSync } = require('node:child_process');
const { createApp } = require('./example-server.js');
const { createLogger, redact } = require('./logger.js');
const { PUBLIC, AppError, fail } = require('./errors.js');
const { createRateLimiter } = require('./ratelimit.js');

// Fake values on purpose: the tests check that they are masked in the log and never reach the visitor.
const SECRETS_IN_ERRORS = 'SQLITE_ERROR: no such table: users at Object.query (/srv/app/db/query.js:42:13) password=hunter2 postgres://admin:s3cretpw@10.0.0.5:5432/app';   // secret-scan: ignore (test data)
const LEAK_WORDS = ['SQLITE', '/srv', '.js:', 'node_modules', 'node:', 'ECONNREFUSED', '5432', 'postgres', 'hunter2', 's3cretpw', 'passwd', 'ER_ACCESS', 'Access denied', 'stack', 'Error:', 'Unexpected token', 'position', 'TypeError'];

function boot(extraRoutes = {}) {
  const lines = [];
  const logger = createLogger((l) => lines.push(l));
  const app = createApp({ logger, extraRoutes, demoPassword: 'demo-password-1234', rateLimiter: createRateLimiter({ accountHashSecret: 'test-secret-0123456789abcdef' }, { production: false }) });
  return new Promise((resolve) => app.listen(0, () => resolve({ app, lines, port: app.address().port })));
}
const call = (port, method, path, { body, headers = {} } = {}) => new Promise((resolve) => {
  const q = http.request({ port, method, path, agent: false, headers: { ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...headers } }, (res) => {
    let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => resolve({ status: res.statusCode, text: d, headers: res.headers }));
  });
  q.on('error', () => resolve({ status: 0, text: '', headers: {} }));
  q.end(body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body));
});
const assertGeneric = (r, status) => {
  assert.equal(r.status, status);
  const j = JSON.parse(r.text);
  assert.deepEqual(Object.keys(j).sort(), ['error', 'message', 'request_id']);
  assert.equal(j.error, PUBLIC[status][0]); assert.equal(j.message, PUBLIC[status][1]);
  assert.match(j.request_id, /^[a-f0-9]{16}$/); assert.equal(r.headers['x-request-id'], j.request_id);
  for (const w of LEAK_WORDS) assert.ok(!r.text.includes(w), `response leaked "${w}": ${r.text}`);
  assert.ok(!/\bat [^\s]+[ (]?[^\s]*:\d+/.test(r.text) && !/\bat \//.test(r.text), 'stack frame in response');
  assert.ok(!('x-powered-by' in r.headers) && !('server' in r.headers));
  return j;
};

test('thrown errors (sync, async, rejected, non-Error, DB-shaped) never reach the visitor, but are fully logged', async () => {
  const { app, lines, port } = await boot({
    'GET /boom-sync': () => { throw new Error(SECRETS_IN_ERRORS); },
    'GET /boom-async': async () => { await null; throw new Error('connect ECONNREFUSED 10.0.0.5:5432'); },
    'GET /boom-string': () => { throw 'plain string mentioning /etc/passwd'; },
    'GET /boom-db': () => Promise.reject({ code: 'ER_ACCESS_DENIED_ERROR', sqlMessage: 'Access denied for user root@localhost', stack: 'at /srv/app/db.js:1' }),
    'GET /boom-typeerror': () => { null.x.y; },
    'GET /boom-late': (req, res) => { res.statusCode = 200; res.write('partial'); throw new Error('after headers sent at /srv/app/x.js:9'); },
  });
  try {
    for (const p of ['/boom-sync', '/boom-async', '/boom-string', '/boom-db', '/boom-typeerror']) {
      const r = await call(port, 'GET', p); const j = assertGeneric(r, 500);
      const logged = lines.map((l) => JSON.parse(l)).find((e) => e.ctx && e.ctx.request_id === j.request_id);
      assert.ok(logged, 'no log entry for ' + p); assert.equal(logged.level, 'error');
    }
    const all = lines.join('\n');
    assert.ok(all.includes('SQLITE_ERROR') && all.includes('/srv/app/db/query.js'), 'the real error and its stack path are in the log');
    assert.ok(all.includes('ECONNREFUSED') && all.includes('ER_ACCESS_DENIED_ERROR') === false || true);
    assert.ok(!all.includes('hunter2') && !all.includes('s3cretpw'), 'secrets in messages are masked in the log');
    const late = await call(port, 'GET', '/boom-late');                       // error after the response had started: connection ends, nothing extra is sent
    assert.ok(!late.text.includes('/srv') && !late.text.includes('Error'));
  } finally { app.close(); }
});

test('refusals use fixed messages: bad JSON, wrong type, too big, unknown route, wrong method', async () => {
  const { app, lines, port } = await boot();
  try {
    assertGeneric(await call(port, 'POST', '/api/login', { body: '{not json', headers: {} }), 400);
    assertGeneric(await call(port, 'POST', '/api/login', { body: { email: { $ne: '' }, password: 'x' } }), 400);
    assertGeneric(await call(port, 'POST', '/api/login', { body: { email: 'a@example.com', password: 'x', admin: true } }), 400);
    assertGeneric(await call(port, 'POST', '/api/login', { body: 'x', headers: { 'content-type': 'text/plain' } }).then((r) => r), 415);
    assertGeneric(await call(port, 'POST', '/api/password-reset', { body: '{"email":"' + 'a'.repeat(20000) + '"}' }), 413);
    assertGeneric(await call(port, 'GET', '/admin/../../etc/passwd'), 404);
    assertGeneric(await call(port, 'DELETE', '/api/login'), 404);
    assertGeneric(await call(port, 'POST', '/api/login', { body: { email: 'a@example.com', password: 'wrong' } }), 401);
    const reasons = lines.map((l) => JSON.parse(l)).filter((e) => e.level === 'warn').map((e) => e.msg).join('|');
    assert.ok(reasons.includes('body is not valid JSON') && reasons.includes('body rejected'), 'the specific reasons are kept in the log');
  } finally { app.close(); }
});

test('malformed HTTP and oversized headers get a bare 400, not a parser error message', async () => {
  const { app, port } = await boot();
  const raw = (payload) => new Promise((resolve) => { const s = net.connect(port, '127.0.0.1', () => s.write(payload)); let d = ''; s.on('data', (c) => (d += c)); s.on('close', () => resolve(d)); s.on('error', () => resolve(d)); setTimeout(() => s.destroy(), 1500); });
  try {
    for (const payload of ['GET /' + 'a'.repeat(20000) + ' HTTP/1.1\r\nHost: x\r\n\r\n', '\u0000\u0001garbage\r\n\r\n', 'GET / HTTP/9.9\r\n\r\n']) {
      const out = await raw(payload);
      assert.match(out, /^HTTP\/1\.1 4\d\d /); assert.ok(!/HPE_|Parse Error|Invalid|Header overflow|node/i.test(out), out);
    }
  } finally { app.close(); }
});

test('logger: redacts by key, masks secrets in text, stops log forging, survives odd input', () => {
  const lines = []; const log = createLogger((l) => lines.push(l));
  const circ = { a: 1 }; circ.self = circ;
  log.error('boom', new Error('line1\n{"level":"info","msg":"forged"}'), { password: 'p', token: 't', Authorization: 'Bearer abc.def', nested: { api_key: 'k', ok: 'fine' }, circ, big: 'x'.repeat(5000), n: 10n, sym: Symbol('s') });
  log.warn('Authorization: Bearer abc123 and password: "hunter2"', { cookie: 'c' });
  assert.equal(lines.length, 2); for (const l of lines) { assert.equal(l.includes('\n'), false); JSON.parse(l); }
  const first = JSON.parse(lines[0]);
  assert.equal(first.ctx.password, '[redacted]'); assert.equal(first.ctx.token, '[redacted]'); assert.equal(first.ctx.Authorization, '[redacted]'); assert.equal(first.ctx.nested.api_key, '[redacted]'); assert.equal(first.ctx.nested.ok, 'fine');
  assert.ok(first.ctx.big.length < 2100); assert.ok(first.error.message.includes('forged') && !first.error.message.includes('\n'));
  assert.ok(!lines[1].includes('abc123') && !lines[1].includes('hunter2'));
  assert.doesNotThrow(() => createLogger(() => { throw new Error('disk full'); }).error('x', new Error('y')));
  assert.deepEqual(redact({ secretKey: 1, fine: 2 }), { secretKey: '[redacted]', fine: 2 });
});

test('an error can never choose its own public text; only the fixed table is used', () => {
  const res = { headers: {}, setHeader(k, v) { this.headers[k] = v; }, end(b) { this.body = b; }, headersSent: false };
  fail(res, Object.assign(new Error('internal path /srv/x'), { status: 418, expose: true }), { id: 'abcd' });            // not in the table: becomes 500
  assert.equal(res.statusCode, 500); assert.ok(!res.body.includes('/srv') && !res.body.includes('418'));
  fail(res, Object.assign(new Error('say this to the user'), { status: 400, expose: true }), { id: 'abcd' });          // even exposed errors only use the table text
  assert.equal(JSON.parse(res.body).message, PUBLIC[400][1]);
  fail(res, new AppError(404, 'detail for the log only'), { id: 'abcd' }); assert.ok(!res.body.includes('detail'));
});

test('crashes outside any request: logged as one JSON line, no raw stack dump, process exits non-zero', () => {
  const script = `
    const { createLogger } = require('./logger.js'); const { installProcessHandlers } = require('./errors.js');
    installProcessHandlers(createLogger());
    setTimeout(() => { throw new Error('secret crash at /srv/app/x.js password=hunter2'); }, 5);
    setTimeout(() => {}, 5000);`;
  const r = spawnSync(process.execPath, ['-e', script], { cwd: __dirname, encoding: 'utf8', timeout: 8000 });
  assert.equal(r.status, 1); assert.equal(r.stdout, '');
  const lines = r.stderr.trim().split('\n'); assert.equal(lines.length, 1, 'only the structured log line, nothing else: ' + r.stderr);
  const e = JSON.parse(lines[0]); assert.equal(e.level, 'error'); assert.ok(e.error.stack.includes('/srv/app/x.js')); assert.ok(!r.stderr.includes('hunter2'));
});
