# Security report

Covers the three checks you asked for. Everything below was run, not just written.

## 1. Strict input validation
Every input is checked against a schema (type, length, format) and **rejected** if it doesn't match. Nothing is trimmed, cut short or repaired.

| Where | What changed |
|---|---|
| Add Video form, Add Template form | Each entry is built, then checked by a schema: required fields, allowed choices (category, link type, licence), lengths, formats, no `<` or `>`, no control characters, no unknown fields. The form shows the exact reason it was refused. |
| `MY_VIDEOS` / `MY_TEMPLATES` lists | Each line checked the same way. A bad line is skipped and a warning goes to the browser console. The lists themselves are capped at 200 KB and 500 entries. |
| Saved entries in the browser | Same schema on every read; more than 50 entries or 300 KB is refused. |
| YouTube links | Must be a real `https` link on a YouTube address in a known shape. Before, an ID anywhere in the text was accepted. |
| Template links | `https` only, 12 to 480 characters, no spaces or quotes, no username or password in the link, no port, no raw IP address. |
| Search and sort boxes | Over 100 characters, control characters or an unknown sort value are refused. |
| Backend module | `validate.js` does the same for request bodies (email, password, numbers, lists). Wrong type, bad format, extra fields and `__proto__` tricks are all `400`. Account names, user ids and IP addresses are checked before they touch any counter. |

Tested with 87 hostile and valid inputs on the site validators, 24 tests on the backend, and 15 real HTTP requests against the example server (not JSON, wrong content type, object instead of text, extra field, oversized body, and so on). All behave as intended.
Escaping on output is still there as a second layer.

## 2. Secrets
- **Scanned:** every project file and all the versions you uploaded, with `scripts/secret-scan.py` (cloud keys, GitHub and API tokens, private keys, JWTs, credentials in URLs, passwords compared or assigned to literals, long random strings, values from a `.env` file appearing elsewhere). The scanner was tested against planted secrets and safe code.
- **Found and fixed (all in the backend code I wrote earlier, none in the website):**
  1. a fixed fallback key (`'rl'`) for hashing account names. Now it comes from `RL_ACCOUNT_HASH_SECRET`, or a random key per run; production refuses to start without one; keys under 16 characters are refused.
  2. a hardcoded demo password in `example-server.js`. Now `DEMO_PASSWORD` from the environment.
  3. a placeholder secret in the README. Replaced with a command that generates one.
- **Website:** `index.html` has no keys, tokens, passwords or emails. It has no build step and reads no environment variables, so nothing can leak into it from one. Embedded images contain no GPS or camera data. The two embedded videos carry only an encoder name.
- **Git:** `.gitignore` blocks `.env`, keys and certificates; `.env.example` shows the shape with no values; `scripts/pre-commit` blocks a commit that contains a secret; the GitHub workflow scans files and full history on every push.
- **Not something I could check:** your actual git history. Run this once in your repository:
  `git log --all -p | python3 scripts/secret-scan.py --stdin`
  If it finds a real key, **change that key at the service that issued it.** Deleting it from git is not enough, because the old commit still contains it.
- Also switch on GitHub's own **secret scanning** and **push protection** (Settings > Code security).

## 3. Dependency audit
- **Packages:** none. The website has no npm or script libraries, the backend uses only Node's built-in modules, and the tools use only Python's standard library. `npm audit` ran and reported 0 vulnerabilities, but with no packages that is trivially true.
- **Outside services the page uses:** Google Fonts (stylesheet and font files), YouTube (player and thumbnails), and links to YouTube and Instagram. These can't be audited with npm. They are limited by the security policy, and the YouTube player runs in a sandbox. Self-hosting the fonts would remove the Google dependency.
- **Staying safe over time:** `package.json` pins nothing because there is nothing to pin; if you ever add a package, Dependabot (weekly) and the workflow's `npm audit` (every push and every Monday) will flag vulnerable versions. `scripts/audit-deps.py` lists every dependency and flags any package or unknown website.

## 4. Error handling
- **Website:** reviewed all 29 `catch` blocks and every place text is shown. No error object, message or stack trace is ever put on the page; failures show fixed messages ("Something didn't load right", "Try again"). Added a handler for unhandled promise failures, and a plain `404.html` so a missing page never shows a host's default error page. The browser console only ever receives the short validation reasons.
- **Backend:** new `errors.js` and `logger.js`. Visitors only ever get a fixed message and a request id; full detail (message, stack, paths, database errors) goes to the log under the same id, with passwords, tokens, cookies and keys masked and log-forging blocked. Tested with errors shaped like database failures, stack traces with file paths, thrown strings, rejected promises, errors after a response had started, malformed HTTP, and a crash outside any request. None of it reached the response.

## 5. File uploads
- **Website:** there is no upload code at all: no file input, no FileReader, no FormData, no network calls. The "Upload Video" and "Add Template" pages only take links. Self-hosted videos are files you commit yourself; their paths are checked (plain `.mp4` or `.webm` names, no `..`).
- **Backend:** new `uploads.js`, ready for when you add real uploads: content-based type and structure checks, per-type size limits, random file names, storage outside the web root with owner-only permissions and no execute bit, and inert serving. See `backend/README.md`.
- **Tested** with disguised files (exe, html, svg and php posing as video or image), appended and hidden code, corrupt files, size lies, bad file names, planted symlinks, and unsafe settings. I also switched each protection off in turn to check the tests fail when it's missing.

## What I can't promise
No site is unhackable. This reduces the ways in. The biggest remaining risk is someone getting into your GitHub, YouTube or Instagram accounts, so keep two-factor authentication on for all three.
