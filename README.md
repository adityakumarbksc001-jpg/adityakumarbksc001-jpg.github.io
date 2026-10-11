# Aditya Kumar: video editing portfolio

One self-contained page (`index.html`), no build step and no server. Host the folder on GitHub Pages, Netlify or Cloudflare Pages.

## What's in the folder
| Path | What it is |
|---|---|
| `index.html` | The whole website |
| `sw.js` | Lets the site open offline after the first visit |
| `404.html` | Plain "page not found" page |
| `.well-known/security.txt` | Tells people how to report a security problem |
| `.nojekyll` | Makes GitHub Pages serve the `.well-known` folder |
| `_headers` | Extra security headers (used by Netlify and Cloudflare Pages; GitHub Pages ignores it) |
| `csp-hash.py` | Refreshes the security-policy fingerprints after you edit code |
| `scripts/` | Secret scanner, dependency check, git hook |
| `.github/` | Automatic weekly and per-push security checks |
| `.gitignore`, `.env.example` | Keep secrets out of git |
| `SECURITY.md`, `SECURITY-REPORT.md` | Security policy and what was checked |
| `backend/` | Optional server toolkit; not used by the site |

## Add a video or template
1. Put the video on YouTube.
2. On the site open **Upload Video** (or **Templates, then Add Template**), fill in the form, and press the add button.
3. Copy the line it shows. Paste it inside the `MY_VIDEOS` (or `MY_TEMPLATES`) block near the top of `index.html`, then commit.

Editing those lists does not need anything else. If you change the **code** in `index.html`, run `python3 csp-hash.py index.html` before committing, or the browser will block the edited script.

## Before the first push
Install the commit guard once: `cp scripts/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit`
