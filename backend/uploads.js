'use strict';
/**
 * Safe file uploads (no third-party packages).
 *   - The file's CONTENT decides what it is (magic bytes plus structure checks), not its name or the Content-Type header.
 *     The header and the file name must agree with the content, or the upload is refused.
 *   - Only the types in the allow-list are accepted (mp4, webm, jpeg, png, webp). Everything else is refused.
 *   - Size is limited per type, checked up front (Content-Length) and again while the bytes arrive.
 *   - Files are stored under a random name we choose (never the visitor's file name), in a folder OUTSIDE the web root,
 *     with owner-only permissions and no execute bit. The server refuses to start if the folder is inside the web root.
 *   - Files are only ever sent back as inert data: fixed Content-Type, nosniff, a sandboxed CSP, never run or imported.
 * Every refusal is an AppError: the visitor gets a generic message, the reason goes to the log.
 */
const fs = require('node:fs');
const fsp = fs.promises;
const path = require('node:path');
const crypto = require('node:crypto');
const { AppError } = require('./errors.js');
const { deepMerge, envTree } = require('./ratelimit.js');

const MB = 1024 * 1024;
const DEFAULTS = {
  dir: '',                  // UPLOAD_DIR: absolute path, OUTSIDE the folder your web server serves
  webRoot: '',              // WEB_ROOT: the folder your web server serves. Uploads may not be inside it.
  maxFilesPerUser: 50,
  maxBytesPerUser: 1024 * MB,
  types: {
    mp4:  { mime: 'video/mp4',  ext: 'mp4',  maxBytes: 200 * MB },
    webm: { mime: 'video/webm', ext: 'webm', maxBytes: 200 * MB },
    jpeg: { mime: 'image/jpeg', ext: 'jpg',  maxBytes: 5 * MB },
    png:  { mime: 'image/png',  ext: 'png',  maxBytes: 5 * MB },
    webp: { mime: 'image/webp', ext: 'webp', maxBytes: 5 * MB },
  },
};
const KINDS = Object.keys(DEFAULTS.types);

/* ---------------- configuration ---------------- */
function loadUploadConfig({ env = process.env, overrides } = {}) {
  let cfg = deepMerge(DEFAULTS, envTree(env, 'UP__'));
  if (env && env.UPLOAD_DIR) cfg.dir = env.UPLOAD_DIR;
  if (env && env.WEB_ROOT) cfg.webRoot = env.WEB_ROOT;
  return deepMerge(cfg, overrides || {});
}
function validateConfig(cfg, production) {
  const bad = (m) => { throw new Error('upload config: ' + m); };
  if (typeof cfg.dir !== 'string' || !cfg.dir || cfg.dir.includes('\0') || !path.isAbsolute(cfg.dir)) bad('UPLOAD_DIR must be an absolute path');
  if (typeof cfg.webRoot !== 'string' || cfg.webRoot.includes('\0')) bad('WEB_ROOT is not valid');
  if (production && !cfg.webRoot) bad('WEB_ROOT must be set in production so the server can prove uploads are outside it');
  for (const k of ['maxFilesPerUser', 'maxBytesPerUser']) if (!Number.isInteger(cfg[k]) || cfg[k] < 1) bad(`${k} must be a whole number >= 1`);
  for (const [k, t] of Object.entries(cfg.types)) {
    if (!KINDS.includes(k)) bad(`unknown type "${k}"`);
    if (!t || t.mime !== DEFAULTS.types[k].mime) bad(`types.${k}.mime cannot be changed`);
    if (!/^[a-z0-9]{2,5}$/.test(t.ext)) bad(`types.${k}.ext is not valid`);
    if (!Number.isInteger(t.maxBytes) || t.maxBytes < 1) bad(`types.${k}.maxBytes must be a whole number >= 1`);
  }
  return cfg;
}
function isInside(child, parent) {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/* ---------------- content checks ---------------- */
const CRC_TABLE = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(buf) { let c = 0xffffffff; for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }

function sniff(h) {          // what the first bytes say the file is
  if (h.length >= 12 && h.toString('latin1', 4, 8) === 'ftyp') return 'mp4';
  if (h.length >= 4 && h.readUInt32BE(0) === 0x1a45dfa3) return 'webm';
  if (h.length >= 3 && h[0] === 0xff && h[1] === 0xd8 && h[2] === 0xff) return 'jpeg';
  if (h.length >= 8 && h.compare(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), 0, 8, 0, 8) === 0) return 'png';
  if (h.length >= 12 && h.toString('latin1', 0, 4) === 'RIFF' && h.toString('latin1', 8, 12) === 'WEBP') return 'webp';
  return null;
}
const MP4_BRANDS = new Set(['isom', 'iso2', 'iso4', 'iso5', 'iso6', 'mp41', 'mp42', 'avc1', 'M4V ', 'M4A ', 'dash', 'msdh', 'f4v ', 'mmp4']);
const CHECKS = {   // each returns '' when the structure is sound, otherwise the reason (for the log only)
  async mp4(r) {
    if (r.size < 24) return 'too small';
    const head = await r.read(0, 12);
    if (!MP4_BRANDS.has(head.toString('latin1', 8, 12))) return 'unknown brand';
    let off = 0, ftyp = false, data = false, n = 0;
    while (off < r.size) {                                   // walk every top-level box; they must fill the file exactly
      if (++n > 10000) return 'too many boxes';
      if (r.size - off < 8) return 'truncated box';
      const h = await r.read(off, 16);
      let size = h.readUInt32BE(0), hdr = 8;
      const type = h.toString('latin1', 4, 8);
      if (!/^[\x20-\x7e]{4}$/.test(type)) return 'bad box type';
      if (size === 1) { if (r.size - off < 16) return 'bad box'; const big = h.readBigUInt64BE(8); if (big > BigInt(Number.MAX_SAFE_INTEGER)) return 'bad box'; size = Number(big); hdr = 16; }
      else if (size === 0) size = r.size - off;
      if (size < hdr || off + size > r.size) return 'box size does not fit';
      if (n === 1 && type !== 'ftyp') return 'ftyp not first';
      if (type === 'ftyp') ftyp = true;
      if (type === 'moov' || type === 'mdat') data = true;
      off += size;
    }
    return ftyp && data ? '' : 'missing boxes';
  },
  async webm(r) {
    if (r.size < 32) return 'too small';
    const h = await r.read(0, 16);
    const b = h[4]; let len = 1, mask = 0x80;
    while (len <= 8 && !(b & mask)) { len++; mask >>= 1; }
    if (len > 4) return 'bad EBML size';
    let size = b & (mask - 1); for (let i = 1; i < len; i++) size = size * 256 + h[4 + i];
    if (size < 8 || size > 1024) return 'bad EBML header';
    const end = 4 + len + size;
    if (end + 4 > r.size) return 'truncated';
    const hdr = await r.read(4 + len, size);
    if (!hdr.includes(Buffer.from([0x42, 0x82, 0x84, 0x77, 0x65, 0x62, 0x6d]))) return 'not a webm DocType';
    return (await r.read(end, 4)).readUInt32BE(0) === 0x18538067 ? '' : 'no Segment after header';
  },
  async jpeg(r) {
    if (r.size < 20) return 'too small';
    const z = await r.read(r.size - 2, 2);
    return z[0] === 0xff && z[1] === 0xd9 ? '' : 'does not end at the JPEG end marker (extra data?)';
  },
  async png(r) {
    if (r.size > 32 * MB) return 'too large to inspect';
    const b = await r.read(0, r.size);
    let pos = 8, n = 0, seenEnd = false;
    while (pos < b.length) {
      if (++n > 20000) return 'too many chunks';
      if (b.length - pos < 12) return 'truncated chunk';
      const len = b.readUInt32BE(pos), type = b.toString('latin1', pos + 4, pos + 8);
      if (len > 0x7fffffff || pos + 12 + len > b.length) return 'chunk does not fit';
      if (!/^[A-Za-z]{4}$/.test(type)) return 'bad chunk type';
      if (n === 1 && (type !== 'IHDR' || len !== 13)) return 'IHDR not first';
      if (crc32(b.subarray(pos + 4, pos + 8 + len)) !== b.readUInt32BE(pos + 8 + len)) return 'chunk checksum wrong';
      pos += 12 + len;
      if (type === 'IEND') { seenEnd = true; break; }
    }
    return seenEnd && pos === b.length ? '' : 'missing IEND or extra data after it';
  },
  async webp(r) {
    if (r.size < 30) return 'too small';
    const h = await r.read(0, 16);
    if (h.readUInt32LE(4) + 8 !== r.size) return 'RIFF size does not match the file (extra data?)';
    return ['VP8 ', 'VP8L', 'VP8X'].includes(h.toString('latin1', 12, 16)) ? '' : 'unknown first chunk';
  },
};
const SCRIPT_SIGS = ['<?php', '<script', '<%@ page', '#!/bin/', '#!/usr/', 'eval(base64_decode'];   // 5+ bytes: random video data will not match these
const hasScript = (s) => { s = s.toLowerCase(); return SCRIPT_SIGS.some((x) => s.includes(x)); };

const NEVER = new Set(['php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'js', 'mjs', 'cjs', 'html', 'htm', 'xhtml', 'shtml', 'svg', 'xml', 'exe', 'dll', 'so', 'bat', 'cmd', 'com', 'sh', 'bash', 'ps1', 'py', 'pl', 'rb', 'cgi', 'asp', 'aspx', 'jsp', 'jspx', 'jar', 'war', 'htaccess', 'htpasswd', 'lnk', 'scr', 'msi', 'vbs', 'wsf']);
const NAME_EXT = { mp4: ['mp4', 'm4v'], webm: ['webm'], jpeg: ['jpg', 'jpeg'], png: ['png'], webp: ['webp'] };
function nameProblem(name, kind) {        // '' when fine. A file name is optional, and is only ever checked, never stored or used.
  if (name === undefined) return '';
  if (typeof name !== 'string' || name.length < 3 || name.length > 100) return 'file name length';
  if (!/^[A-Za-z0-9][A-Za-z0-9 ._()-]*[A-Za-z0-9)]$/.test(name)) return 'file name characters';
  const parts = name.toLowerCase().split('.');
  if (parts.length < 2) return 'no extension';
  if (parts.slice(1).some((p) => NEVER.has(p.trim()))) return 'executable-looking extension in the name';
  return NAME_EXT[kind].includes(parts[parts.length - 1]) ? '' : 'extension does not match the content';
}

/* ---------------- storage ---------------- */
class UploadStore {
  constructor(config, { logger, production } = {}) {
    this.cfg = validateConfig(config, production);
    this.logger = logger;
    fs.mkdirSync(this.cfg.dir, { recursive: true, mode: 0o700 });
    fs.chmodSync(this.cfg.dir, 0o700);
    this.dir = fs.realpathSync(this.cfg.dir);
    if (path.parse(this.dir).root === this.dir) throw new Error('upload config: UPLOAD_DIR cannot be the filesystem root');
    if (this.cfg.webRoot) {
      const wr = fs.existsSync(this.cfg.webRoot) ? fs.realpathSync(this.cfg.webRoot) : path.resolve(this.cfg.webRoot);
      if (isInside(this.dir, wr)) throw new Error('upload config: UPLOAD_DIR must be outside WEB_ROOT');
    } else if (logger) logger.warn('WEB_ROOT is not set, so the server cannot check that uploads are outside the web root');
    for (const f of fs.readdirSync(this.dir)) if (f.startsWith('.tmp-')) fs.rmSync(path.join(this.dir, f), { force: true });   // leftovers from a crash
    this.usage = new Map();
  }

  async save(stream, { contentType, contentLength, filename, userId } = {}) {
    const mime = String(contentType || '').split(';')[0].trim().toLowerCase();
    const kind = KINDS.find((k) => this.cfg.types[k] && this.cfg.types[k].mime === mime);
    if (!kind) throw new AppError(415, 'declared type not allowed', { contentType: mime.slice(0, 60) });
    const t = this.cfg.types[kind];
    let declared;
    if (contentLength !== undefined) {
      if (!/^\d{1,12}$/.test(String(contentLength))) throw new AppError(400, 'bad Content-Length');
      declared = Number(contentLength);
      if (declared > t.maxBytes) throw new AppError(413, 'declared size over the limit', { declared, max: t.maxBytes });
    }
    const u = this.usage.get(userId) || { files: 0, bytes: 0 };
    if (u.files + 1 > this.cfg.maxFilesPerUser || u.bytes + (declared || 0) > this.cfg.maxBytesPerUser) throw new AppError(403, 'upload quota reached', { userId });

    const tmp = path.join(this.dir, '.tmp-' + crypto.randomBytes(16).toString('hex'));
    const fh = await fsp.open(tmp, 'wx+', 0o600);            // exclusive: never follows or overwrites anything that already exists
    try {
      let total = 0, head = Buffer.alloc(0), carry = '';
      for await (const chunk of stream) {
        total += chunk.length;
        if (total > t.maxBytes) throw new AppError(413, 'size over the limit while receiving', { max: t.maxBytes });
        if (head.length < 16) {
          head = Buffer.concat([head, chunk]).subarray(0, 16);
          if (head.length >= 12 && sniff(head) !== kind) throw new AppError(415, 'content does not match the declared type', { sniffed: sniff(head) });
        }
        const text = carry + chunk.toString('latin1');
        if (hasScript(text)) throw new AppError(400, 'script-like content found');
        carry = text.slice(-24);
        let o = 0; while (o < chunk.length) { const { bytesWritten } = await fh.write(chunk, o, chunk.length - o); o += bytesWritten; }
      }
      if (total === 0) throw new AppError(400, 'empty upload');
      if (declared !== undefined && declared !== total) throw new AppError(400, 'size differs from Content-Length');
      if (sniff(head) !== kind) throw new AppError(415, 'content does not match the declared type', { sniffed: sniff(head) });
      const why = await CHECKS[kind]({ size: total, read: async (off, len) => { const b = Buffer.alloc(len); const { bytesRead } = await fh.read(b, 0, len, off); return b.subarray(0, bytesRead); } });
      if (why) throw new AppError(400, 'content check failed: ' + why);
      const np = nameProblem(filename, kind);
      if (np) throw new AppError(400, 'file name refused: ' + np);

      const id = crypto.randomBytes(16).toString('hex');
      const name = `${id}.${t.ext}`;                          // our name, not theirs
      await fh.close();
      await fsp.link(tmp, path.join(this.dir, name));          // fails if the name somehow exists: never overwrites
      await fsp.unlink(tmp);
      await fsp.chmod(path.join(this.dir, name), 0o600);       // owner read/write only, no execute bit
      this.usage.set(userId, { files: u.files + 1, bytes: u.bytes + total });
      return { id, name, type: t.mime, size: total };
    } catch (e) {
      try { await fh.close(); } catch { /* already closed */ }
      await fsp.unlink(tmp).catch(() => {});
      throw e;
    }
  }

  async open(id) {
    if (typeof id !== 'string' || !/^[a-f0-9]{32}$/.test(id)) throw new AppError(404, 'bad file id');
    for (const k of KINDS) {
      const t = this.cfg.types[k]; if (!t) continue;
      const p = path.join(this.dir, `${id}.${t.ext}`);
      let st; try { st = await fsp.lstat(p); } catch { continue; }
      if (!st.isFile() || st.isSymbolicLink()) throw new AppError(404, 'not a regular file');
      if (!isInside(await fsp.realpath(p), this.dir)) throw new AppError(404, 'resolved outside the upload folder');
      return { path: p, mime: t.mime, size: st.size, name: `${id}.${t.ext}` };
    }
    throw new AppError(404, 'no such file');
  }

  async serve(req, res, id) {
    if (req.method !== 'GET' && req.method !== 'HEAD') throw new AppError(405, 'method');
    const f = await this.open(id);
    let start = 0, end = f.size - 1, status = 200;
    const range = req.headers.range;
    if (range !== undefined) {
      const m = /^bytes=(\d*)-(\d*)$/.exec(range);
      if (!m || (m[1] === '' && m[2] === '')) throw new AppError(400, 'bad Range');
      if (m[1] === '') { start = Math.max(0, f.size - Number(m[2])); } else { start = Number(m[1]); if (m[2] !== '') end = Math.min(end, Number(m[2])); }
      if (start > end || start >= f.size) { res.setHeader('Content-Range', `bytes */${f.size}`); res.statusCode = 416; return res.end(); }
      status = 206;
    }
    res.statusCode = status;
    res.setHeader('Content-Type', f.mime);                                            // fixed by us from the detected type
    res.setHeader('Content-Length', String(end - start + 1));
    res.setHeader('Accept-Ranges', 'bytes');
    if (status === 206) res.setHeader('Content-Range', `bytes ${start}-${end}/${f.size}`);
    res.setHeader('X-Content-Type-Options', 'nosniff');                               // the browser must not guess a different type
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");           // even if opened directly, it can run nothing
    res.setHeader('Content-Disposition', `inline; filename="${f.name}"`);
    res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
    res.setHeader('Cache-Control', 'private, max-age=3600');
    if (req.method === 'HEAD') return res.end();
    await new Promise((resolve) => {
      const rs = fs.createReadStream(f.path, { start, end });
      rs.on('error', (e) => { if (this.logger) this.logger.error('upload read failed', e, { name: f.name }); res.destroy(); resolve(); });
      res.on('close', resolve); rs.pipe(res);
    });
  }
}
module.exports = { UploadStore, loadUploadConfig, DEFAULTS, sniff, CHECKS, nameProblem, crc32, hasScript, isInside };
