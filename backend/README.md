# Backend toolkit (optional)

> **Not used by the website.** GitHub Pages only serves static files, so nothing in this folder runs there. It is a tested, dependency-free toolkit (rate limiting, strict input checks, safe errors, safe uploads) for the day you add a server, such as a contact form or accounts. You can leave it in the repository or delete the folder; the checks in `.github` adapt either way.

A dependency-free rate limiter with three tiers, for the day you add a backend (contact form, accounts, comments).
Your current site is static, so it has no endpoints for this to protect.

| Tier | Used for | Default | Keyed by |
|---|---|---|---|
| `public` | pages and read-only API calls | 60 per minute | client IP |
| `authenticated` | actions by a signed-in user | 300 per minute | user id |
| `auth.login` | sign in | 30 per 15 min per IP, 10 per 15 min per account | IP **and** account |
| `auth.signup` | create account | 10 per hour per IP, 3 per hour per account | IP **and** account |
| `auth.passwordReset` | request a reset | 10 per hour per IP, 3 per hour per account | IP **and** account |

## How the auth routes behave
- **Per IP and per account, both checked.** One IP trying many accounts, or many IPs trying one account, both get slowed.
- **Exponential backoff, no hard lockout.** After a few free failures each failure adds a delay: `baseSec × factor^n`, capped at `maxSec`. The delay is forgotten after `resetAfterSec` of quiet, and a successful login clears the account's delay.
- A shared IP (school, office) gets more free failures (`ipFreeFailures`) than a single account.
- Signup and password reset count **every attempt**, not only failures (`"on": "attempt"`).
- Every refusal is the same `429` with `Retry-After`, so an attacker can't tell which limit fired or whether an account exists. The real reason goes to your private `onBlock` log.

## Use it
```js
const { createRateLimiter, loadConfig } = require('./ratelimit.js');
const rl = createRateLimiter(loadConfig());

app.get('/api/projects', rl.publicMiddleware());
app.post('/api/login', rl.authMiddleware('login', (req) => req.body.email), (req, res) => {
  const ok = checkPassword(req.body);          // your code
  ok ? req.rateLimit.succeed() : req.rateLimit.fail();
  /* ...respond... */
});
app.post('/api/videos', rl.userMiddleware((req) => req.session.userId), handler);
```
`example-server.js` is a runnable version (`RL_ACCOUNT_HASH_SECRET=$(openssl rand -hex 32) DEMO_PASSWORD=<12+ characters> node example-server.js`).

## Strict input checks (`validate.js`)
Every request body is checked against a schema (type, length, format) and **rejected** with `400` if anything is off: wrong type, too long, bad format, control characters, missing or unexpected fields. Nothing is trimmed, cut or repaired. Account names and user ids are also checked before they reach any counter, so junk can't fill memory.

## Errors: visitors see a fixed message, you see everything (`errors.js`, `logger.js`)
- Every failure goes through one place. The visitor gets one of a few fixed messages plus a `request_id`; an error's own text, stack trace, file paths or database messages can never be sent, whatever they say.
- The full detail goes to the log as one JSON line carrying the same `request_id`, so a user can quote it and you can find it. Passwords, tokens, cookies and keys are masked, and line breaks are stripped so nobody can forge log lines.
- Errors thrown anywhere (sync, async, rejected promises, strings, database-shaped objects), malformed HTTP, and crashes outside a request are all covered; the process logs the crash and exits so your host restarts it cleanly.

## File uploads (`uploads.js`)
The website itself has no upload feature (its "Upload Video" page only takes a YouTube link). This module is for when you add one.
- **Content decides, not the name:** magic bytes plus a structure check per type (mp4, webm, jpeg, png, webp). The Content-Type header and the file name must agree with the content, or it's refused. Anything else (svg, html, php, exe, and so on) is refused.
- **Size:** per-type limits, checked from Content-Length before a byte is read, again while the data arrives, and against lying Content-Lengths.
- **Hidden code:** files with extra data after the real end, broken structure, or script markers (`<?php`, `<script`, shell shebangs) are refused.
- **Storage:** random names we choose (never the visitor's), in `UPLOAD_DIR` outside the web root with owner-only permissions and no execute bit. The server refuses to start if the folder is inside `WEB_ROOT` (symlinks included). Temp files are removed on any failure.
- **Serving:** only by 32-character id, never by path; symlinks are never followed; fixed Content-Type, `nosniff`, a sandboxed CSP. Nothing is ever executed or imported.
- **Still true:** a file can look like a valid video and be nonsense inside. For public sites, also serve uploads from a separate domain or storage bucket, and consider a virus scanner such as ClamAV.

## Configuration: nothing is hardcoded
Order, later wins: built-in defaults, then a JSON file (`RL_CONFIG=path`, see `config.example.json`), then environment variables, then code overrides.
Any value can be an environment variable: `RL__tiers__public__max=120`, `RL__tiers__auth__login__backoff__factor=3`.
Also: `RL_TRUST_PROXY_HOPS`, `RL_ACCOUNT_HASH_SECRET`. Bad values stop the app at start-up with a clear error.

## Set these before going live
- `RL_ACCOUNT_HASH_SECRET`: a long random string (16+ characters), kept in the environment or your host's secrets, never in git. Without it the limiter uses a random key per run, and in production it refuses to start. Account names are never stored, only a keyed hash.
- `trustProxyHops`: how many reverse proxies sit in front (0 if none). A wrong number lets people fake their IP.
- The default store is memory inside one process. With several servers, or for a stronger setup, keep the counters in Redis or use your host's edge rate limiting.

Run the tests: `node --test ratelimit.test.js`
