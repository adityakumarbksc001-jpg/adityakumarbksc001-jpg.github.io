#!/usr/bin/env python3
"""Scan a project for hardcoded secrets and accidental personal data.

  python3 scripts/secret-scan.py                 scan the whole project (run from the project folder)
  python3 scripts/secret-scan.py path1 path2     scan specific files or folders
  python3 scripts/secret-scan.py --staged        scan only what is about to be committed (used by the git hook)

Exit code 1 when something that looks like a secret is found. Standard library only.
To mark a reviewed false positive, add  secret-scan: ignore  in a comment on that line.
"""
import math, os, re, subprocess, sys

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "artifacts"}
BIN_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".mp4", ".webm", ".mov", ".woff", ".woff2", ".ttf", ".otf", ".pdf", ".zip", ".gz"}
BLOB = re.compile(r"data:[a-z]+/[a-z0-9.+-]+;base64,[A-Za-z0-9+/=]{200,}")     # embedded media is checked separately

PATTERNS = [   # (name, regex)
    ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("Slack token", r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
    ("Stripe live key", r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"),
    ("Anthropic / OpenAI style key", r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{32,}\b"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ("JSON web token", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("Credentials in a URL", r"\b[a-z][a-z0-9+.\-]*://[^/\s:@'\"]+:[^/\s:@'\"]+@[^/\s'\"]+"),
]
COMPARE = re.compile(r"""(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_\-]?key)\b[\w.\[\]'"]*\s*[!=]==?\s*["']([^"']{8,})["']""")
ASSIGN = re.compile(r"""(?i)\b(pass(?:word|wd)?|pwd|secret|api[_\-]?key|access[_\-]?key|auth[_\-]?token|token|private[_\-]?key|client[_\-]?secret)\b["']?\s*[:=]\s*["']([^"'\s]{8,})["']""")
PLACEHOLDER = re.compile(r"(?i)^(?:x{4,}|\*+|<.*>|\$\{.*\}|your[_\-].*|change[_\-]?me|example.*|placeholder.*|test[_\-].*|dummy.*|none|null|undefined|process\.env.*|os\.environ.*)$")
INFO = [   # personal data that should not be shipped by accident
    ("email address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}\b")),
    ("local file path", re.compile(r"(?:/Users/|/home/|C:\\Users\\)[A-Za-z0-9._-]+")),
    ("phone number", re.compile(r"(?<![\w.)\]])(?:\+\d{1,3}[ -]?\d{8,12}|\(?\d{3}\)?[ -]\d{3}[ -]\d{4})(?![\w.])")),
]
EMAIL_OK = re.compile(r"(?i)@(example\.(?:com|net|org)|domain\.com|x\.com|a\.com|b\.co|users\.noreply\.github\.com)$")

def entropy(s):
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))

def files(targets, staged):
    if staged:
        out = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"], capture_output=True, text=True).stdout.split()
        yield from (f for f in out if os.path.isfile(f))
        return
    for t in targets or ["."]:
        if os.path.isfile(t):
            yield t
            continue
        for root, dirs, names in os.walk(t):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for n in names:
                yield os.path.join(root, n)

def scan_file(path):
    if os.path.splitext(path)[1].lower() in BIN_EXT:
        return [], []
    try:
        text = open(path, encoding="utf-8").read()
    except (UnicodeDecodeError, OSError):
        return [], []
    return scan_text(text)

def scan_text(text):
    return scan_lines(text.split("\n"))

def scan_lines(lines):
    hits, info = [], []
    for no, line in enumerate(lines, 1):
        line = line.rstrip("\n")
        if "secret-scan: ignore" in line:
            continue
        line = BLOB.sub("data:BLOB", line)
        if len(line) > 5000:
            line = line[:5000]
        for name, rx in PATTERNS:
            if re.search(rx, line):
                hits.append((no, name))
        for m in ASSIGN.finditer(line):
            v = m.group(2)
            if not PLACEHOLDER.match(v):
                hits.append((no, f"hardcoded {m.group(1).lower()} value"))
        for m in COMPARE.finditer(line):            # a password or token compared to a quoted literal
            if not PLACEHOLDER.match(m.group(2)):
                hits.append((no, f"hardcoded {m.group(1).lower()} compared to a literal"))
        for m in re.finditer(r"[\"'`]([A-Za-z0-9+/_\-=]{32,})[\"'`]", line):   # long random-looking strings
            v = m.group(1)
            if "sha256-" in line[max(0, m.start() - 8):m.start() + 8] or v.startswith("sha256-"):
                continue
            if entropy(v) > 4.5 and not re.fullmatch(r"[A-Za-z]+", v):
                hits.append((no, "long high-entropy string"))
        for name, rx in INFO:
            for m in rx.finditer(line):
                if name == "email address" and EMAIL_OK.search(m.group(0)):
                    continue
                info.append((no, name))
    return hits, info

def env_values():
    """Values from a local .env file. They must never appear in any other file (that would ship them)."""
    vals = {}
    if os.path.isfile(".env"):
        for line in open(".env", encoding="utf-8"):
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                v = v.strip().strip("\"'")
                if len(v) >= 8:
                    vals[k.strip()] = v
    return vals

def main():
    args = sys.argv[1:]
    staged = "--staged" in args
    targets = [a for a in args if not a.startswith("--")]
    bad = 0
    if "--stdin" in args:                       # e.g.  git log --all -p | python3 scripts/secret-scan.py --stdin
        hits, _ = scan_lines(sys.stdin)                   # streamed, so a long history does not fill memory
        for no, what in hits:
            print(f"SECRET?  <git history>:{no}  {what}")
        print(f"\n{len(hits)} possible secret(s) found in history." if hits else "\nNo hardcoded secrets found in history.")
        sys.exit(1 if hits else 0)
    env = env_values()
    for f in sorted(set(files(targets, staged))):
        if os.path.basename(f).startswith(".env") and not f.endswith(".example"):
            continue
        if env and os.path.splitext(f)[1].lower() not in BIN_EXT:
            try:
                body = open(f, encoding="utf-8").read()
                for k, v in env.items():
                    if v in body:
                        print(f"SECRET?  {f}  contains the value of {k} from your .env file")
                        bad += 1
            except (UnicodeDecodeError, OSError):
                pass
        hits, info = scan_file(f)
        for no, what in hits:
            print(f"SECRET?  {f}:{no}  {what}")
            bad += 1
        for no, what in info:
            print(f"info     {f}:{no}  {what} (check it is meant to be public)")
    print(f"\n{bad} possible secret(s) found." if bad else "\nNo hardcoded secrets found.")
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()
