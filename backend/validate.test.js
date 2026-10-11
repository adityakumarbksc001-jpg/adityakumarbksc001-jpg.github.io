'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { validate, s } = require('./validate.js');

const login = s.object({ email: s.email(), password: s.password() });
const signup = s.object({ email: s.email(), password: s.password({ min: 12 }) });
const bad = (schema, v) => assert.equal(validate(schema, v).ok, false, JSON.stringify(v));
const good = (schema, v) => assert.equal(validate(schema, v).ok, true, JSON.stringify(v));

test('accepts exactly-right input', () => {
  good(login, { email: 'bob@example.com', password: 'a password with spaces ' });   // passwords are never trimmed
  good(signup, { email: 'a.b+tag@sub.example.co.in', password: 'x'.repeat(12) });
});
test('rejects wrong types instead of converting them', () => {
  for (const v of [null, undefined, 'str', 5, [], [{ email: 'a@b.co', password: 'x' }]]) bad(login, v);
  bad(login, { email: 123, password: 'x' }); bad(login, { email: 'bob@example.com', password: 123 });
  bad(login, { email: { $ne: '' }, password: 'x' }); bad(login, { email: ['bob@example.com'], password: 'x' });   // NoSQL-style objects and arrays
  bad(login, { email: true, password: 'x' });
});
test('rejects missing, extra and prototype-polluting fields', () => {
  bad(login, { email: 'bob@example.com' }); bad(login, { password: 'x' }); bad(login, {});
  bad(login, { email: 'bob@example.com', password: 'x', admin: true });
  bad(login, JSON.parse('{"email":"bob@example.com","password":"x","__proto__":{"admin":true}}'));
  bad(login, JSON.parse('{"email":"bob@example.com","password":"x","constructor":{"a":1}}'));
});
test('rejects bad lengths without truncating', () => {
  bad(login, { email: 'a'.repeat(250) + '@b.co', password: 'x' });
  bad(login, { email: 'bob@example.com', password: '' });
  bad(login, { email: 'bob@example.com', password: 'x'.repeat(129) });
  bad(signup, { email: 'bob@example.com', password: 'x'.repeat(11) });
  bad(login, { email: 'x'.repeat(65) + '@example.com', password: 'x' });
});
test('rejects bad formats and control characters', () => {
  for (const e of ['plain', '@example.com', 'bob@', 'bob@example', 'bob@@example.com', 'bob @example.com', 'bob@exa mple.com', 'bob@example.com ', ' bob@example.com', 'bob@example.com\n', 'bo\u0000b@example.com', 'bob@-example.com', 'bob@example..com', '"quoted"@example.com', 'bob@[127.0.0.1]', '<script>@example.com'])
    bad(login, { email: e, password: 'x' });
  bad(login, { email: 'bob@example.com', password: 'bad\u0000pass' });   // secret-scan: ignore (test input)
});
test('numbers, enums, lists and booleans are strict too', () => {
  const sc = s.object({ n: s.integer({ min: 1, max: 10 }), c: s.string({ en: ['a', 'b'], max: 5 }), l: s.array(s.string({ min: 1, max: 3 }), { max: 2 }), b: s.boolean() });
  good(sc, { n: 5, c: 'a', l: ['x'], b: true });
  bad(sc, { n: '5', c: 'a', l: [], b: true }); bad(sc, { n: 5.5, c: 'a', l: [], b: true }); bad(sc, { n: 11, c: 'a', l: [], b: true });
  bad(sc, { n: NaN, c: 'a', l: [], b: true }); bad(sc, { n: Infinity, c: 'a', l: [], b: true });
  bad(sc, { n: 5, c: 'z', l: [], b: true }); bad(sc, { n: 5, c: 'a', l: ['x', 'y', 'z'], b: true }); bad(sc, { n: 5, c: 'a', l: ['toolong'], b: true });
  bad(sc, { n: 5, c: 'a', l: [], b: 'true' }); bad(sc, { n: 5, c: 'a', l: 'x', b: true });
});
