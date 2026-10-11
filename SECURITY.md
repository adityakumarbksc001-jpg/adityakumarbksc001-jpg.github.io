# Security

## Reporting a problem
If you find a security issue on this site, please message me on Instagram (@itz_editya.404)
instead of posting it publicly. I'll reply as soon as I can.

## What this site does
- Static site: no accounts, no database, no server code.
- A strict Content Security Policy: only the page's own scripts can run, and only
  YouTube, YouTube thumbnails and Google Fonts can be loaded.
- Every video and template entry is checked before it is shown, and all text is escaped.
- The YouTube player runs in a sandbox, and external links open with `noopener noreferrer`.

## Keeping it safe (owner checklist)
- Two-factor authentication or a passkey on GitHub, YouTube, Instagram and your email.
- Settings > Pages > tick **Enforce HTTPS**.
- Don't add other collaborators to the repository; never commit passwords or keys.
- After editing code (not the video/template lists), run `python3 csp-hash.py index.html`.
