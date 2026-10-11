#!/usr/bin/env python3
"""Refresh the Content-Security-Policy script fingerprints after you edit the CODE in index.html.

Usage:   python3 csp-hash.py index.html          (update)
         python3 csp-hash.py --check index.html  (only check; exit 1 if out of date)
Run it every time you change anything inside a plain <script> ... </script> block.
(Editing the MY_VIDEOS / MY_TEMPLATES lists does NOT need this.)
If a file named _headers sits next to index.html, it is updated too.
"""
import re, sys, os, hashlib, base64

check_only = "--check" in sys.argv
args = [a for a in sys.argv[1:] if not a.startswith("--")]
path = args[0] if args else "index.html"
text = open(path, encoding="utf-8").read()

hashes = ["'sha256-" + base64.b64encode(hashlib.sha256(m.group(1).encode("utf-8")).digest()).decode() + "'"
          for m in re.finditer(r"<script>(.*?)</script>", text, re.S)]
new = "script-src " + " ".join(hashes)
pat = re.compile(r"script-src [^;\"]*")

if not pat.search(text):
    sys.exit("Could not find a script-src rule in the security policy of " + path)

if check_only:                      # used by the git hook and CI: fail if the fingerprints are out of date
    current = pat.search(text).group(0)
    if current.strip() != new.strip():
        sys.exit("Security policy fingerprints are out of date. Run: python3 csp-hash.py " + path)
    print("Security policy fingerprints are up to date (" + str(len(hashes)) + " scripts)")
    sys.exit(0)
open(path, "w", encoding="utf-8").write(pat.sub(lambda m: new, text, count=1))
print("Updated", path, "-", len(hashes), "scripts fingerprinted")

hp = os.path.join(os.path.dirname(os.path.abspath(path)), "_headers")
if os.path.exists(hp):
    h = open(hp, encoding="utf-8").read()
    if pat.search(h):
        open(hp, "w", encoding="utf-8").write(pat.sub(lambda m: new, h, count=1))
        print("Updated", hp)
