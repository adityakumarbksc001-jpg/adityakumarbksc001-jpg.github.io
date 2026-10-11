'use strict';
// Shows where each protection goes: rate limits, strict input checks, safe errors, safe uploads. Plain Node, no packages.
// Run:  RL_ACCOUNT_HASH_SECRET=$(openssl rand -hex 32) DEMO_PASSWORD=<12+ characters> \
//       UPLOAD_DIR=/var/lib/portfolio-uploads WEB_ROOT=/var/www/site node example-server.js
const http = require('node:http');
const crypto = require('node:crypto');
const { createRateLimiter, loadConfig } = require('./ratelimit.js');
const { validate, s } = require('./validate.js');
const { AppError, send, guard, installProcessHandlers } = require('./errors.js');
const { createLogger } = require('./logger.js');
const { UploadStore, loadUploadConfig } = require('./uploads.js');

const MAX_BODY = 10000;
const email = s.email();

function createApp(opts = {}) {
  const logger = opts.logger || createLogger();
  const rl = opts.rateLimiter || createRateLimiter(loadConfig(), { onBlock: (b) => logger.warn('rate limited', b) });
  const uploads = opts.uploads || null;
  const DEMO = opts.demoPassword !== undefined ? opts.demoPassword : (process.env.DEMO_PASSWORD || '');   // never hardcode a password
  const sameSecret = (a, b) => b.length >= 12 && crypto.timingSafeEqual(crypto.createHash('sha256').update(a).digest(), crypto.createHash('sha256').update(b).digest());

  const pub = rl.publicMiddleware();
  const userMw = rl.userMiddleware((r) => r.userId);
  const routes = {   // 'METHOD /path' -> [body schema or null, route limiter or null]
    'GET /api/projects':        [null, null],
    'POST /api/login':          [s.object({ email, password: s.password() }), rl.authMiddleware('login', (r) => r.body.email)],
    'POST /api/signup':         [s.object({ email, password: s.password({ min: 12 }) }), rl.authMiddleware('signup', (r) => r.body.email)],
    'POST /api/password-reset': [s.object({ email }), rl.authMiddleware('passwordReset', (r) => r.body.email)],
    'POST /api/videos':         [s.object({ title: s.string({ min: 1, max: 100, re: /^[^<>]+$/, fmt: 'cannot contain < or >' }) }), userMw],
  };
  const extra = opts.extraRoutes || {};            // test hook only
  const runMw = (mw, req, res) => new Promise((resolve) => { res.once('finish', () => resolve(false)); res.once('close', () => resolve(false)); mw(req, res, () => resolve(true)); });

  async function readJson(req) {
    const chunks = []; let n = 0;
    for await (const c of req) { n += c.length; if (n > MAX_BODY) throw new AppError(413, 'body too large'); chunks.push(c); }
    try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch (e) { throw new AppError(400, 'body is not valid JSON'); }
  }

  const handler = async (req, res, id) => {
    const path = String(req.url || '').split('?')[0];
    const key = `${req.method} ${path}`;
    if (extra[key]) return extra[key](req, res, id);

    if (uploads && /^\/files\//.test(path) && (req.method === 'GET' || req.method === 'HEAD')) {
      if (!(await runMw(pub, req, res))) return;
      return uploads.serve(req, res, path.slice(7));                       // id is checked inside: 32 hex characters or 404
    }
    if (uploads && key === 'PUT /api/uploads') {
      if (!(await runMw(pub, req, res))) return;
      req.userId = req.headers['x-demo-user'] || null;                       // replace with your real session lookup
      if (!req.userId) throw new AppError(401, 'not signed in');
      if (!(await runMw(userMw, req, res))) return;
      try {
        const r = await uploads.save(req, { contentType: req.headers['content-type'], contentLength: req.headers['content-length'], filename: req.headers['x-filename'], userId: String(req.userId) });
        res.statusCode = 201; res.setHeader('Content-Type', 'application/json'); res.setHeader('X-Request-Id', id);
        return res.end(JSON.stringify({ id: r.id, type: r.type, size: r.size }));
      } catch (e) { res.setHeader('Connection', 'close'); res.once('finish', () => req.destroy()); throw e; }   // stop reading a refused upload
    }

    const route = routes[key];
    if (!route) throw new AppError(404, 'no such route');
    if (!(await runMw(pub, req, res))) return;                               // 1. every request counts against the public limit first
    const [schema, limiter] = route;
    if (schema) {
      if (!/^application\/json(?:;|$)/i.test(req.headers['content-type'] || '')) throw new AppError(415, 'not JSON');
      let body;
      try { body = await readJson(req); } catch (e) { res.setHeader('Connection', 'close'); throw e; }
      const v = validate(schema, body);                                       // 2. strict: wrong shape, type, length or format is rejected
      if (!v.ok) throw new AppError(400, 'body rejected: ' + v.error);        //    the reason is logged, the visitor gets the generic message
      req.body = body;
      req.userId = req.headers['x-demo-user'] || null;
    }
    if (limiter && !(await runMw(limiter, req, res))) return;                // 3. then the route's own limiter
    if (key === 'POST /api/login') {
      const ok = sameSecret(req.body.password, DEMO);                         // your real credential check goes here
      ok ? req.rateLimit.succeed() : req.rateLimit.fail();
      if (!ok) throw new AppError(401, 'wrong credentials');
      return send200(res, { ok: true }, id);
    }
    send200(res, { ok: true }, id);
  };
  function send200(res, obj, id) { res.statusCode = 200; res.setHeader('Content-Type', 'application/json'); res.setHeader('X-Request-Id', id); res.end(JSON.stringify(obj)); }

  const server = http.createServer(guard(handler, logger));
  server.on('clientError', (err, socket) => {                                // malformed HTTP: generic reply, details to the log
    logger.warn('client error', { code: err && err.code });
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'); else socket.destroy();
  });
  server.on('error', (e) => logger.error('server error', e));
  return server;
}
module.exports = { createApp };

if (require.main === module) {
  const logger = createLogger();
  installProcessHandlers(logger);
  let uploads = null;
  try {
    const production = process.env.NODE_ENV === 'production';
    if (process.env.UPLOAD_DIR) uploads = new UploadStore(loadUploadConfig(), { logger, production });
    createApp({ logger, uploads }).listen(process.env.PORT || 3000, () => console.log('listening'));
  } catch (e) { logger.error('failed to start', e); console.error('Could not start. See the log for details.'); process.exit(1); }
}
