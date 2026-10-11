'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const zlib = require('node:zlib');
const { Readable } = require('node:stream');
const { UploadStore, loadUploadConfig, DEFAULTS, crc32 } = require('./uploads.js');
const { AppError, PUBLIC } = require('./errors.js');
const { createApp } = require('./example-server.js');
const { createLogger } = require('./logger.js');
const { createRateLimiter } = require('./ratelimit.js');

/* ---------- tiny valid files ---------- */
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const box = (type, payload = Buffer.alloc(0)) => Buffer.concat([u32(8 + payload.length), Buffer.from(type, 'latin1'), payload]);
const mp4 = (mdat = Buffer.from('12345678')) => Buffer.concat([box('ftyp', Buffer.concat([Buffer.from('isom'), u32(512), Buffer.from('isom')])), box('moov'), box('mdat', mdat)]);
const webm = () => Buffer.concat([Buffer.from([0x1a, 0x45, 0xdf, 0xa3, 0x8b, 0x42, 0x86, 0x81, 0x01, 0x42, 0x82, 0x84, 0x77, 0x65, 0x62, 0x6d]), Buffer.from([0x18, 0x53, 0x80, 0x67, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]), Buffer.alloc(20)]);
const chunk = (type, data) => { const t = Buffer.from(type, 'latin1'); return Buffer.concat([u32(data.length), t, data, u32(crc32(Buffer.concat([t, data])))]); };
const png = () => Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', Buffer.from([0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0])), chunk('IDAT', zlib.deflateSync(Buffer.from([0, 0]))), chunk('IEND', Buffer.alloc(0))]);
const jpeg = () => Buffer.from('ffd8ffe000104a46494600010100000100010000ffd9', 'hex');
const webp = () => { const body = Buffer.concat([Buffer.from('VP8 '), Buffer.from([10, 0, 0, 0]), Buffer.alloc(10)]); const size = Buffer.alloc(4); size.writeUInt32LE(4 + body.length); return Buffer.concat([Buffer.from('RIFF'), size, Buffer.from('WEBP'), body]); };
const GOOD = { 'video/mp4': mp4, 'video/webm': webm, 'image/jpeg': jpeg, 'image/png': png, 'image/webp': webp };

/* ---------- helpers ---------- */
const tmp = (n) => fs.mkdtempSync(path.join(os.tmpdir(), n + '-'));
function store(overrides = {}, opts = {}) {
  const root = tmp('up'); const dir = path.join(root, 'private-uploads'); const webRoot = path.join(root, 'www'); fs.mkdirSync(webRoot);
  const cfg = loadUploadConfig({ env: {}, overrides: { dir, webRoot, ...overrides } });
  return { st: new UploadStore(cfg, { production: true, ...opts }), dir, webRoot, root };
}
const stream = (buf, size = 7000) => Readable.from((function* () { for (let i = 0; i < buf.length; i += size) yield buf.subarray(i, i + size); })());
const files = (dir) => fs.readdirSync(dir);
const save = (st, buf, type, extra = {}) => st.save(stream(buf), { contentType: type, contentLength: String(buf.length), userId: 'u1', ...extra });
async function refused(st, dir, run, status) {
  await assert.rejects(run, (e) => e instanceof AppError && (status === undefined || e.status === status), 'expected a refusal' + (status ? ' ' + status : ''));
  assert.deepEqual(files(dir), [], 'nothing may be left behind after a refused upload');
}

test('valid files of every allowed type are accepted and stored safely', async () => {
  const { st, dir, webRoot } = store();
  for (const [type, make] of Object.entries(GOOD)) {
    const buf = make(); const r = await save(st, buf, type, { filename: 'My Edit (final).' + DEFAULTS.types[Object.keys(DEFAULTS.types).find((k) => DEFAULTS.types[k].mime === type)].ext });
    assert.match(r.name, /^[a-f0-9]{32}\.(mp4|webm|jpg|png|webp)$/); assert.equal(r.size, buf.length); assert.equal(r.type, type);
    const p = path.join(dir, r.name);
    assert.ok(fs.readFileSync(p).equals(buf), 'stored bytes are exactly what was sent');
    const mode = fs.statSync(p).mode & 0o777; assert.equal(mode & 0o111, 0, 'no execute bit'); assert.equal(mode & 0o077, 0, 'owner only');
    assert.throws(() => fs.accessSync(p, fs.constants.X_OK), 'the OS refuses to execute it');
    assert.ok(!r.name.includes('Edit'), "the visitor's file name is never used");
  }
  assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
  assert.ok(!path.relative(webRoot, dir).split(path.sep).every((x) => x !== '..'), 'upload folder is not inside the web root');
  assert.equal(files(dir).filter((f) => f.startsWith('.tmp-')).length, 0);
  assert.equal(new Set(files(dir)).size, 5);
});

test('the declared type must be on the allow-list', async () => {
  const { st, dir } = store();
  for (const t of ['image/svg+xml', 'text/html', 'application/x-httpd-php', 'application/octet-stream', 'application/x-msdownload', 'image/gif', 'video/quicktime', '', undefined, 'video/mp4/../x'])
    await refused(st, dir, () => save(st, mp4(), t), 415);
});

test('content wins over the header and the name: disguised files are refused', async () => {
  const { st, dir } = store();
  const exe = Buffer.concat([Buffer.from('MZ'), Buffer.alloc(200, 0x90), Buffer.from('This program cannot be run in DOS mode')]);
  const elf = Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46]), Buffer.alloc(200)]);
  const html = Buffer.from('<html><body><script>fetch("//evil")</script></body></html>'.padEnd(200, ' '));
  const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>'.padEnd(200, ' '));
  const phpAsJpg = Buffer.concat([Buffer.from('ffd8ffe0', 'hex'), Buffer.from('<?php system($_GET["c"]); ?>'.padEnd(100, ' ')), Buffer.from('ffd9', 'hex')]);
  for (const [name, buf, type] of [['exe as mp4', exe, 'video/mp4'], ['elf as webm', elf, 'video/webm'], ['html as png', html, 'image/png'], ['svg as jpeg', svg, 'image/jpeg'], ['png as mp4', png(), 'video/mp4'], ['mp4 as png', mp4(), 'image/png'], ['jpeg as webp', jpeg(), 'image/webp'], ['php as jpeg', phpAsJpg, 'image/jpeg']])
    await refused(st, dir, () => save(st, buf, type), undefined).catch((e) => { throw new Error(name + ': ' + e.message); });
});

test('hidden payloads are refused: appended code, code inside the data, broken structure', async () => {
  const { st, dir } = store();
  const php = Buffer.from('<?php system($_GET["c"]); ?>');
  const cases = {
    'mp4 + appended php': [Buffer.concat([mp4(), php]), 'video/mp4'],
    'mp4 + appended junk': [Buffer.concat([mp4(), Buffer.from('AAAAAAAAAAAAAAAA')]), 'video/mp4'],
    'php inside mp4 data': [mp4(Buffer.concat([Buffer.alloc(20), php])), 'video/mp4'],
    'script inside mp4 data': [mp4(Buffer.from('xx<SCRIPT src=//evil>yy')), 'video/mp4'],
    'mp4 box too big': [Buffer.concat([box('ftyp', Buffer.concat([Buffer.from('isom'), u32(0), Buffer.from('isom')])), u32(5000), Buffer.from('mdat'), Buffer.alloc(20)]), 'video/mp4'],
    'mp4 unknown brand': [Buffer.concat([box('ftyp', Buffer.concat([Buffer.from('zzzz'), u32(0), Buffer.from('isom')])), box('mdat', Buffer.alloc(16))]), 'video/mp4'],
    'mp4 truncated': [mp4().subarray(0, mp4().length - 3), 'video/mp4'],
    'webm without segment': [Buffer.concat([webm().subarray(0, 16), Buffer.alloc(40, 7)]), 'video/webm'],
    'png bad checksum': [(() => { const b = png(); b[40] ^= 0xff; return b; })(), 'image/png'],
    'png + data after IEND': [Buffer.concat([png(), php]), 'image/png'],
    'png without IEND': [png().subarray(0, png().length - 12), 'image/png'],
    'jpeg + trailing data': [Buffer.concat([jpeg(), php]), 'image/jpeg'],
    'jpeg + trailing junk': [Buffer.concat([jpeg(), Buffer.from('JUNKJUNKJUNKJUNK')]), 'image/jpeg'],
    'webp + trailing data': [Buffer.concat([webp(), Buffer.from('trailing')]), 'image/webp'],
    'empty': [Buffer.alloc(0), 'video/mp4'],
    'tiny': [Buffer.from('abc'), 'image/png'],
  };
  for (const [name, [buf, type]] of Object.entries(cases)) await refused(st, dir, () => st.save(stream(buf), { contentType: type, contentLength: String(buf.length), userId: 'u1' }), undefined).catch((e) => { throw new Error(name + ': ' + e.message); });
});

test('size limits: checked before reading, again while receiving, and against Content-Length lies', async () => {
  const { st, dir } = store({ types: { mp4: { mime: 'video/mp4', ext: 'mp4', maxBytes: 1000 } } });
  let reads = 0; const watched = new Readable({ read() { reads++; this.push(null); } });
  await refused(st, dir, () => st.save(watched, { contentType: 'video/mp4', contentLength: '999999999', userId: 'u1' }), 413);
  assert.equal(reads, 0, 'an oversized upload is refused without reading a single byte');
  const big = mp4(Buffer.alloc(5000, 1));
  await refused(st, dir, () => st.save(stream(big, 400), { contentType: 'video/mp4', userId: 'u1' }), 413);        // no Content-Length: stopped mid-stream
  const ok = mp4(Buffer.alloc(100, 1));
  await refused(st, dir, () => st.save(stream(ok), { contentType: 'video/mp4', contentLength: '50', userId: 'u1' }), 400);     // claims less than it sends
  await refused(st, dir, () => st.save(stream(ok), { contentType: 'video/mp4', contentLength: '5000', userId: 'u1' }), 413);    // claims more than the limit
  for (const bad of ['abc', '-5', '1e9', '12.5', '', '99999999999999999']) await refused(st, dir, () => st.save(stream(ok), { contentType: 'video/mp4', contentLength: bad, userId: 'u1' }));
  assert.ok((await st.save(stream(ok), { contentType: 'video/mp4', contentLength: String(ok.length), userId: 'u1' })).size === ok.length);
});

test('file names are only checked, never trusted or stored', async () => {
  const { st, dir } = store();
  const bad = ['../../etc/passwd.mp4', '..\\..\\win.mp4', 'shell.php', 'shell.php.mp4', 'a.mp4.php', 'x.png', 'x\u0000.mp4', '.htaccess', 'a'.repeat(101) + '.mp4', 'noext', 'a b.mp4 ', '/abs/path.mp4', 'a<b>.mp4', 'a.js.mp4', 'run.exe.mp4', 'a.html', 'a.svg'];
  for (const name of bad) await refused(st, dir, () => save(st, mp4(), 'video/mp4', { filename: name }), 400).catch((e) => { throw new Error(JSON.stringify(name) + ': ' + e.message); });
  for (const name of ['clip.mp4', 'My Edit (final).mp4', 'holiday-2026_v2.MP4', 'js.mp4', 'a.m4v']) await save(st, mp4(), 'video/mp4', { filename: name });
  for (const f of files(dir)) assert.match(f, /^[a-f0-9]{32}\.mp4$/);
});

test('quotas per user', async () => {
  const { st, dir } = store({ maxFilesPerUser: 2 });
  await save(st, mp4(), 'video/mp4'); await save(st, mp4(), 'video/mp4');
  await assert.rejects(save(st, mp4(), 'video/mp4'), (e) => e.status === 403);
  await save(st, mp4(), 'video/mp4', { userId: 'someone-else' });
  assert.equal(files(dir).length, 3);
  const b = store({ maxBytesPerUser: 100 }); await assert.rejects(save(b.st, mp4(Buffer.alloc(200)), 'video/mp4'), (e) => e.status === 403);
});

test('concurrent uploads never collide or leave temp files', async () => {
  const { st, dir } = store();
  const r = await Promise.all(Array.from({ length: 20 }, (_, i) => save(st, mp4(Buffer.alloc(50 + i, i)), 'video/mp4', { userId: 'u' + (i % 3) })));
  assert.equal(new Set(r.map((x) => x.id)).size, 20); assert.equal(files(dir).length, 20);
});

test('the server refuses to start with unsafe storage settings', () => {
  const root = tmp('cfg'); const web = path.join(root, 'www'); fs.mkdirSync(path.join(web, 'uploads'), { recursive: true });
  const mk = (o, p = true) => new UploadStore(loadUploadConfig({ env: {}, overrides: o }), { production: p });
  assert.throws(() => mk({ dir: 'relative/uploads', webRoot: web }), /absolute/);
  assert.throws(() => mk({ dir: '', webRoot: web }), /absolute/);
  assert.throws(() => mk({ dir: path.join(web, 'uploads'), webRoot: web }), /outside WEB_ROOT/);
  assert.throws(() => mk({ dir: web, webRoot: web }), /outside WEB_ROOT/);
  assert.throws(() => mk({ dir: path.join(web, 'a', 'b'), webRoot: web }), /outside WEB_ROOT/);
  const link = path.join(root, 'looks-outside'); fs.symlinkSync(path.join(web, 'uploads'), link);
  assert.throws(() => mk({ dir: link, webRoot: web }), /outside WEB_ROOT/);                          // a symlink into the web root is caught
  assert.throws(() => mk({ dir: path.join(root, 'private') }), /WEB_ROOT must be set in production/);
  assert.throws(() => mk({ dir: '/', webRoot: web }, false), /root|outside/);
  assert.throws(() => mk({ dir: path.join(root, 'p2'), webRoot: web, types: { exe: { mime: 'application/x-msdownload', ext: 'exe', maxBytes: 5 } } }), /unknown type/);
  assert.throws(() => mk({ dir: path.join(root, 'p3'), webRoot: web, types: { mp4: { mime: 'text/html', ext: 'mp4', maxBytes: 5 } } }), /mime cannot be changed/);
  assert.throws(() => mk({ dir: path.join(root, 'p4'), webRoot: web, types: { mp4: { mime: 'video/mp4', ext: 'php', maxBytes: 0 } } }), /maxBytes|ext/);
  assert.doesNotThrow(() => mk({ dir: path.join(root, 'ok'), webRoot: web }));
  const cfg = loadUploadConfig({ env: { UPLOAD_DIR: path.join(root, 'fromenv'), WEB_ROOT: web, UP__types__mp4__maxBytes: '1234' } });
  assert.equal(cfg.types.mp4.maxBytes, 1234); assert.equal(cfg.dir, path.join(root, 'fromenv'));       // thresholds come from the environment
  fs.writeFileSync(path.join(root, 'ok', '.tmp-leftover'), 'x'); new UploadStore(loadUploadConfig({ env: {}, overrides: { dir: path.join(root, 'ok'), webRoot: web } }), { production: true });
  assert.deepEqual(files(path.join(root, 'ok')), []);                                                  // crash leftovers are cleaned at start
});

/* ---------- end to end over HTTP ---------- */
async function boot(storeOverrides) {
  const s = store(storeOverrides); const lines = [];
  const logger = createLogger((l) => lines.push(l));
  const app = createApp({ logger, uploads: s.st, demoPassword: 'demo-password-1234', rateLimiter: createRateLimiter({ accountHashSecret: 'test-secret-0123456789abcdef' }, { production: false }) });
  await new Promise((r) => app.listen(0, r));
  return { ...s, app, lines, port: app.address().port };
}
const call = (port, method, p, { body, headers = {} } = {}) => new Promise((resolve) => {
  const q = http.request({ port, method, path: p, agent: false, headers }, (res) => { const c = []; res.on('data', (d) => c.push(d)); res.on('end', () => resolve({ status: res.statusCode, buf: Buffer.concat(c), headers: res.headers })); });
  q.on('error', () => resolve({ status: 0, buf: Buffer.alloc(0), headers: {} })); q.end(body);
});
const text = (r) => r.buf.toString('latin1');

test('HTTP: upload, fetch back, and every refusal is generic', async () => {
  const { app, port, dir, root, lines } = await boot();
  try {
    const good = mp4(Buffer.alloc(3000, 5));
    const up = await call(port, 'PUT', '/api/uploads', { body: good, headers: { 'content-type': 'video/mp4', 'content-length': good.length, 'x-demo-user': 'u1', 'x-filename': 'clip.mp4' } });
    assert.equal(up.status, 201); const { id } = JSON.parse(text(up)); assert.match(id, /^[a-f0-9]{32}$/);

    const got = await call(port, 'GET', '/files/' + id);
    assert.equal(got.status, 200); assert.ok(got.buf.equals(good));
    assert.equal(got.headers['content-type'], 'video/mp4'); assert.equal(got.headers['x-content-type-options'], 'nosniff');
    assert.match(got.headers['content-security-policy'], /sandbox/); assert.equal(got.headers['cross-origin-resource-policy'], 'same-site');
    const part = await call(port, 'GET', '/files/' + id, { headers: { range: 'bytes=10-19' } });
    assert.equal(part.status, 206); assert.equal(part.buf.length, 10); assert.ok(part.buf.equals(good.subarray(10, 20)));
    assert.equal((await call(port, 'GET', '/files/' + id, { headers: { range: 'bytes=999999-' } })).status, 416);
    assert.equal((await call(port, 'HEAD', '/files/' + id)).status, 200);

    const attempts = [
      ['not signed in', { 'content-type': 'video/mp4', 'content-length': good.length }, good, 401],
      ['php named .php', { 'content-type': 'video/mp4', 'x-demo-user': 'u1', 'x-filename': 'shell.php' }, good, 400],
      ['svg', { 'content-type': 'image/svg+xml', 'x-demo-user': 'u1' }, Buffer.from('<svg onload=alert(1)>'), 415],
      ['html', { 'content-type': 'text/html', 'x-demo-user': 'u1' }, Buffer.from('<script>1</script>'), 415],
      ['exe as mp4', { 'content-type': 'video/mp4', 'x-demo-user': 'u1' }, Buffer.concat([Buffer.from('MZ'), Buffer.alloc(300)]), 415],
      ['mp4 + php', { 'content-type': 'video/mp4', 'x-demo-user': 'u1' }, Buffer.concat([good, Buffer.from('<?php evil(); ?>')]), 400],
    ];
    for (const [name, headers, body, want] of attempts) {
      const r = await call(port, 'PUT', '/api/uploads', { body, headers });
      assert.equal(r.status, want, name); const j = JSON.parse(text(r));
      assert.deepEqual(Object.keys(j).sort(), ['error', 'message', 'request_id']);
      assert.equal(j.message, PUBLIC[want][1], name);
      for (const w of [dir, root, 'content check', 'script-like', 'structure', 'sniff', 'ftyp', 'php', 'extension', '.tmp', 'mdat', 'Error']) assert.ok(!text(r).includes(w), `${name} leaked "${w}"`);
    }
    assert.ok(lines.join('\n').includes('script-like content found'), 'but the log says exactly why');
    assert.equal(files(dir).filter((f) => !f.endsWith('.mp4')).length, 0);

    for (const bad of ['/files/' + '0'.repeat(32), '/files/' + id.toUpperCase(), '/files/' + id.slice(1), '/files/..%2f..%2fetc%2fpasswd', '/files/../../etc/passwd', '/files/' + id + '%00.php', '/files/' + id + '.mp4', '/files/%2e%2e/' + id, '/files/', '/files/' + id + '/x', '/files/' + id.replace(/./, '%')]) {
      const r = await call(port, 'GET', bad); assert.ok([404, 400].includes(r.status), bad + ' -> ' + r.status);
      assert.ok(!text(r).includes('root:') && !text(r).includes(dir));
    }
    fs.symlinkSync('/etc/passwd', path.join(dir, 'c'.repeat(32) + '.mp4'));                             // a planted symlink must never be followed
    const sym = await call(port, 'GET', '/files/' + 'c'.repeat(32)); assert.equal(sym.status, 404); assert.ok(!text(sym).includes('root:'));
    assert.equal((await call(port, 'POST', '/files/' + id)).status, 404);
  } finally { app.close(); }
});

test('HTTP: a huge upload is cut off and nothing is left on disk', async () => {
  const { app, port, dir } = await boot({ types: { mp4: { mime: 'video/mp4', ext: 'mp4', maxBytes: 2000 } } });
  try {
    const r = await call(port, 'PUT', '/api/uploads', { body: mp4(Buffer.alloc(50000)), headers: { 'content-type': 'video/mp4', 'x-demo-user': 'u1', 'transfer-encoding': 'chunked' } });
    assert.ok([413, 0].includes(r.status)); await new Promise((r2) => setTimeout(r2, 100)); assert.deepEqual(files(dir), []);
  } finally { app.close(); }
});
