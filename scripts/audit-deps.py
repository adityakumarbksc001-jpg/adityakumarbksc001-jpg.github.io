#!/usr/bin/env python3
"""List everything this project depends on, and flag anything that is not built in.

  python3 scripts/audit-deps.py

Finds npm packages (package.json), JavaScript require()/import, Python imports, and the outside websites the page loads.
It cannot look up known vulnerabilities by itself (that needs an advisory database): run `npm audit` for npm packages
(CI does this every week). Standard library only.
"""
import ast, json, os, re, sys

SKIP = {".git", "node_modules", "__pycache__", "artifacts"}
NODE_BUILTIN = {"assert", "buffer", "child_process", "crypto", "dns", "events", "fs", "http", "http2", "https", "net", "os", "path",
                "perf_hooks", "process", "querystring", "readline", "stream", "string_decoder", "test", "timers", "tls", "url", "util", "worker_threads", "zlib"}
KNOWN_HOSTS = {
    "fonts.googleapis.com": "Google Fonts stylesheet",
    "fonts.gstatic.com": "Google Fonts files",
    "www.youtube-nocookie.com": "YouTube video player (embedded)",
    "i.ytimg.com": "YouTube thumbnails",
    "www.youtube.com": "link to YouTube (opens in a new tab)",
    "youtube.com": "YouTube address check",
    "www.instagram.com": "link to your Instagram (opens in a new tab)",
}
def walk():
    for root, dirs, names in os.walk("."):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for n in names:
            yield os.path.join(root, n)

third, builtin, hosts, py_third = {}, set(), {}, set()
for f in walk():
    ext = os.path.splitext(f)[1]
    try:
        text = open(f, encoding="utf-8").read()
    except (UnicodeDecodeError, OSError):
        continue
    text = re.sub(r"data:[a-z]+/[a-z0-9.+-]+;base64,[A-Za-z0-9+/=]{200,}", "", text)
    if os.path.basename(f) == "package.json":
        pj = json.loads(text)
        for sec in ("dependencies", "devDependencies", "optionalDependencies"):
            for k, v in (pj.get(sec) or {}).items():
                third[k] = f"{v} ({f})"
    if ext in (".js", ".mjs", ".cjs"):
        for m in re.finditer(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)|from\s+['\"]([^'\"]+)['\"]", text):
            mod = m.group(1) or m.group(2)
            if mod.startswith("."):
                continue
            base = mod.replace("node:", "").split("/")[0]
            if mod.startswith("node:") or base in NODE_BUILTIN:
                builtin.add(base)
            else:
                third.setdefault(base, "imported in " + f)
    if ext == ".py":
        try:
            for node in ast.walk(ast.parse(text)):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module] if isinstance(node, ast.ImportFrom) and node.module and not node.level else []
                for n in names:
                    if n.split(".")[0] not in sys.stdlib_module_names:
                        py_third.add(n.split(".")[0])
        except SyntaxError:
            pass
    if ext in (".html", ".js", ".css", ".json", ".yml"):
        for m in re.finditer(r"https?://([A-Za-z0-9.-]+)", text):
            h = m.group(1)
            if h not in ("www.w3.org", "..."):
                hosts[h] = hosts.get(h, 0) + 1
    if ext == ".html":
        for m in re.finditer(r"<script[^>]+src=[\"']([^\"']+)", text):
            third["script:" + m.group(1)] = f"external script in {f}"

print("npm / JavaScript packages (third-party):", ", ".join(f"{k} {v}" for k, v in third.items()) or "none")
print("Node built-in modules used:             ", ", ".join(sorted(builtin)) or "none")
print("Python packages (third-party):          ", ", ".join(sorted(py_third)) or "none (standard library only)")
print("\nOutside websites the project talks to:")
for h, n in sorted(hosts.items()):
    print(f"  {h:28} {KNOWN_HOSTS.get(h, 'UNKNOWN - check this one')}")
unknown = [h for h in hosts if h not in KNOWN_HOSTS]
sys.exit(1 if third or py_third or unknown else 0)
