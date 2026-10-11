'use strict';
/**
 * Strict input validation for request bodies. A value either matches the schema exactly or it is rejected.
 * Nothing is trimmed, cut short, stripped or "fixed". Unknown fields are rejected too.
 *   const r = validate(schema, body);  ->  { ok: true, value } or { ok: false, error }
 */
const NOCTRL = /[\u0000-\u001f\u007f\u2028\u2029]/;
const NOCTRL_NL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u2028\u2029]/;
const EMAIL = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/;
const has = Object.prototype.hasOwnProperty;

const s = {
  string: (o = {}) => ({ t: 'string', min: 0, max: 256, ...o }),    // max is always set: no unbounded strings
  email: (o = {}) => ({ t: 'string', min: 6, max: 254, re: EMAIL, fmt: 'must be a valid email address', ...o }),
  password: (o = {}) => ({ t: 'string', min: 1, max: 128, raw: true, ...o }),   // raw: spaces are allowed, never trimmed
  integer: (o = {}) => ({ t: 'number', int: true, min: 0, max: 2 ** 31 - 1, ...o }),
  boolean: () => ({ t: 'boolean' }),
  array: (of, o = {}) => ({ t: 'array', of, min: 0, max: 50, ...o }),
  object: (props, o = {}) => ({ t: 'object', props, ...o }),
};

function check(r, v, path) {
  if (v === undefined || v === null) return r.opt ? '' : `${path} is required`;
  switch (r.t) {
    case 'string':
      if (typeof v !== 'string') return `${path} must be text`;
      if (v.length < r.min) return `${path} is too short`;
      if (v.length > r.max) return `${path} is too long`;
      if ((r.nl ? NOCTRL_NL : NOCTRL).test(v)) return `${path} has characters that are not allowed`;
      if (!r.raw && v !== v.trim()) return `${path} has spaces at the start or end`;
      if (r.en && !r.en.includes(v)) return `${path} is not an allowed value`;
      if (r.re && !r.re.test(v)) return `${path} ${r.fmt || 'is not in the right format'}`;
      return '';
    case 'number':
      if (typeof v !== 'number' || !Number.isFinite(v)) return `${path} must be a number`;
      if (r.int && !Number.isInteger(v)) return `${path} must be a whole number`;
      return v < r.min || v > r.max ? `${path} is out of range` : '';
    case 'boolean':
      return typeof v === 'boolean' ? '' : `${path} must be true or false`;
    case 'array': {
      if (!Array.isArray(v)) return `${path} must be a list`;
      if (v.length < r.min || v.length > r.max) return `${path} has the wrong number of items`;
      for (let i = 0; i < v.length; i++) { const e = check(r.of, v[i], `${path}[${i}]`); if (e) return e; }
      return '';
    }
    case 'object': {
      if (typeof v !== 'object' || Array.isArray(v)) return `${path} must be an object`;
      for (const k of Object.keys(v)) if (!has.call(r.props, k)) return `${path} has an unexpected field "${k.slice(0, 30)}"`;
      for (const k of Object.keys(r.props)) { const e = check(r.props[k], has.call(v, k) ? v[k] : undefined, k); if (e) return e; }
      return '';
    }
    default: return 'unknown rule';
  }
}
function validate(schema, value) {
  const e = check(schema, value, 'body');
  return e ? { ok: false, error: e } : { ok: true, value };
}
module.exports = { validate, s, NOCTRL, NOCTRL_NL, EMAIL };
