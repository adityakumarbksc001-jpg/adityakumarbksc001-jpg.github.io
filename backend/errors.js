'use strict';
/**
 * One place that decides what a visitor is allowed to see when something goes wrong.
 *   - Visitors get only a short, fixed message and a request id.
 *   - Everything else (the real message, stack trace, file paths, database errors) goes to the log with the same id.
 * An error's own message is NEVER sent to the visitor, whatever it says.
 */
const crypto = require('node:crypto');

const PUBLIC = {   // status -> [code, message]. This table is the only text a visitor can ever receive.
  400: ['invalid_request', 'The request was not valid.'],
  401: ['unauthorized', 'Please sign in to continue.'],
  403: ['forbidden', 'You are not allowed to do that.'],
  404: ['not_found', 'Not found.'],
  405: ['method_not_allowed', 'That method is not allowed.'],
  413: ['payload_too_large', 'That is too large.'],
  415: ['unsupported_media_type', 'That type of content is not accepted.'],
  429: ['too_many_requests', 'Too many requests. Please try again later.'],
  500: ['server_error', 'Something went wrong on our side. Please try again later.'],
  503: ['unavailable', 'This is temporarily unavailable.'],
};
/** Throw this for expected failures. `detail` is for the log only. */
class AppError extends Error {
  constructor(status, detail, extra) {
    super(detail || String((PUBLIC[status] || PUBLIC[500])[0]));
    this.name = 'AppError';
    this.status = PUBLIC[status] ? status : 500;
    this.extra = extra;
  }
}
const requestId = () => crypto.randomBytes(8).toString('hex');

function send(res, status, id) {
  if (res.headersSent) { try { res.end(); } catch { /* socket already gone */ } return; }
  const [code, message] = PUBLIC[status] || PUBLIC[500];
  res.statusCode = PUBLIC[status] ? status : 500;
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (id) res.setHeader('X-Request-Id', id);
  res.end(JSON.stringify({ error: code, message, request_id: id }));
}
/** Use for every failure. Logs full detail, answers with the fixed message. */
function fail(res, err, { logger, id, req, ctx } = {}) {
  const status = err instanceof AppError ? err.status : (Number.isInteger(err && err.status) && PUBLIC[err.status] && err.status < 500 && err.expose === true ? err.status : 500);
  if (logger) {
    const c = { request_id: id, method: req && req.method, path: req && typeof req.url === 'string' ? req.url.split('?')[0].slice(0, 200) : undefined, status, ...(err instanceof AppError && err.extra ? { detail: err.extra } : {}), ...ctx };
    status >= 500 ? logger.error('request failed', err, c) : logger.warn('request refused: ' + (err && err.message), c);
  }
  send(res, status, id);
}
/** Wraps a handler so nothing that is thrown (sync or async) can reach the visitor or crash the server. */
function guard(handler, logger) {
  return (req, res) => {
    const id = requestId();
    req.requestId = id;
    res.on('error', (e) => logger && logger.error('response stream error', e, { request_id: id }));
    req.on('error', (e) => logger && logger.error('request stream error', e, { request_id: id }));
    try {
      Promise.resolve(handler(req, res, id)).catch((e) => fail(res, e, { logger, id, req }));
    } catch (e) { fail(res, e, { logger, id, req }); }
  };
}
/** Last-resort handlers: log everything privately, then exit so a supervisor restarts a clean process. */
function installProcessHandlers(logger, exit = (c) => process.exit(c)) {
  process.on('uncaughtException', (e) => { logger.error('uncaught exception', e); exit(1); });
  process.on('unhandledRejection', (e) => { logger.error('unhandled rejection', e); exit(1); });
}
module.exports = { AppError, PUBLIC, requestId, send, fail, guard, installProcessHandlers };
