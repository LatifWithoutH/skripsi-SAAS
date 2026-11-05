#!/usr/bin/env python3
"""
uji.py - OWASP Top 10:2025 Tester + CVSS v3.1 untuk SI-MITRA-DUDIKA
(Node.js + PostgreSQL + Nginx + Docker)

Cara kerja:
  --target  -> tes dinamis (HTTP, non-destruktif: probe deteksi, bukan eksploitasi)
  --project -> tes statis (analisis source code, dependency, Dockerfile, Nginx)
  Minimal salah satu wajib. Boleh keduanya.
  Setiap temuan (FAIL) diberi skor CVSS v3.1 dari vektor skenario; nilai ini
  adalah estimasi skenario terburuk dan harus divalidasi manual.

PERINGATAN: --target mengirim login gagal berulang, payload probe, dan request
malformed. Gunakan HANYA pada sistem milik sendiri/staging yang diizinkan, dan
wajib sertakan --authorized.

Contoh:
  python3 uji.py --authorized \
      --target https://staging.example.com \
      --project /home/bissmillah/si-mitra-dudika \
      --token-a "<JWT user biasa tenant A>" \
      --idor-path "/api/mitra/{id}" --id-a 12 --id-b 57 \
      --admin-path /api/admin/users \
      --container simitra-backend \
      --json-out hasil_top10.json

  python3 uji.py --project ./si-mitra-dudika            # statis saja
  python3 uji.py --authorized --target https://x --only A01,A05
"""

import argparse
import base64
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from urllib.parse import quote, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# CVSS v3.1 (implementasi mandiri sesuai spesifikasi FIRST)
# ==========================================
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x):
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss31(vector):
    parts = vector.split("/")
    if parts[0] != "CVSS:3.1":
        raise ValueError(f"Bukan vektor CVSS 3.1: {vector}")
    m = dict(p.split(":") for p in parts[1:])
    changed = m["S"] == "C"
    pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.50 if changed else 0.27}[m["PR"]]
    iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + expl) if changed else impact + expl
    return _roundup(min(total, 10))


def cvss_label(score):
    if score == 0:
        return "Informational"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


# Vektor skenario (A-xx dari tabel asli + varian untuk temuan spesifik)
V = {
    "A01_IDOR": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "A01_PRIV": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "A01_UNAUTH_HI": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "A01_UNAUTH_LO": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "A01_FAILOPEN": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "A02": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "A02_FILES": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "A02_CORS": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "A03_CRIT": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "A03_HIGH": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "A03_HYGIENE": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "A04": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N",
    "A04_SECRET": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "A04_TLS": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N",
    "A05_SQLI": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "A05_XSS": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "A05_POTENTIAL": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "A06": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    "A07_BRUTE": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "A07_TOKEN": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
    "A07_NONE": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "A08": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N",
    "A08_RCE": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",
    "A09_AUDIT": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N",
    "A09_LOGS": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "A10": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "A10_5XX": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "A10_LOW": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L",
}

CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging & Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

REKOMENDASI = {
    "A01": "Terapkan otorisasi di setiap endpoint; filter semua query dengan tenant_id dari token (bukan dari input); gunakan RBAC terpusat.",
    "A02": "Set header keamanan via helmet/Nginx, batasi CORS ke origin tertentu, blokir dotfile/backup di Nginx, matikan X-Powered-By.",
    "A03": "Commit lockfile & pakai `npm ci`; jalankan `npm audit fix`/Dependabot; pin versi; hindari dependency dari git/URL.",
    "A04": "Paksa HTTPS+HSTS; hash password dengan bcrypt(>=12)/argon2; semua rahasia dari env/secret manager, jangan commit .env.",
    "A05": "Gunakan query terparameterisasi ($1, $2) atau ORM dengan binding; validasi input (zod/joi); encode output & CSP.",
    "A06": "Lakukan threat modelling multi-tenant; tambahkan rate limit pada alur sensitif dan validasi skema pada semua input.",
    "A07": "Rate limit + lockout pada login; JWT dengan expiresIn pendek & algorithms eksplisit; cookie httpOnly+secure+sameSite.",
    "A08": "Tambahkan SRI untuk script eksternal; hindari `curl | sh` di Dockerfile; pin GitHub Actions ke SHA; hindari deserialisasi tak aman.",
    "A09": "Log terstruktur (winston/pino) untuk event auth/aksi sensitif + tabel audit_logs + alerting; blokir akses file log di Nginx.",
    "A10": "Pasang error handler global & handler unhandledRejection/uncaughtException; jangan bocorkan stack trace; fail-closed.",
}

COMMON_LOG_PATHS = [
    "/logs/", "/log/", "/debug/", "/admin/logs", "/api/logs", "/system/logs",
    "/server.log", "/app.log", "/error.log", "/access.log",
    "/logs/app.log", "/logs/error.log", "/npm-debug.log",
]
LOGIN_PATHS = ["/api/auth/login", "/api/login", "/auth/login", "/login"]
DEFAULT_PROTECTED = ["/api/users", "/api/admin", "/api/admin/users", "/api/tenants",
                     "/api/me", "/api/profile", "/api/mitra"]
DEFAULT_PROBE = ["/api/search?q=", "/api/mitra?search=", "/api/mitra?q=",
                 "/api/users?search=", "/?q="]
EXPOSED_FILES = {
    "/.env": re.compile(r"^[A-Z][A-Z0-9_]{2,}=.+", re.M),
    "/.git/HEAD": re.compile(r"^ref:\s*refs/"),
    "/.git/config": re.compile(r"\[core\]"),
    "/package.json": re.compile(r'"(dependencies|scripts|name)"\s*:'),
    "/docker-compose.yml": re.compile(r"^\s*services:", re.M),
    "/Dockerfile": re.compile(r"^\s*FROM\s+\S+", re.M | re.I),
    "/backup.sql": re.compile(r"CREATE TABLE|INSERT INTO", re.I),
    "/dump.sql": re.compile(r"CREATE TABLE|INSERT INTO", re.I),
    "/.npmrc": re.compile(r"_authToken|registry="),
}
LOGGING_FRAMEWORKS = ["winston", "morgan", "pino", "bunyan", "log4js", "express-winston",
                      "pino-http", "winston-daily-rotate-file"]
AUDIT_KEYWORDS = ["audit_log", "audit_logs", "audit_trail", "activity_log", "activity_logs",
                  "event_log", "change_history"]

SQL_ERRORS = re.compile(
    r"syntax error at or near|unterminated quoted string|SequelizeDatabaseError|"
    r"invalid input syntax for|unclosed quotation mark|error in your SQL syntax|"
    r"\bPG::|SQLITE_ERROR|ORA-\d{5}|error: column .* does not exist|PrismaClientKnownRequestError",
    re.I)
LEAK_PATTERNS = [
    re.compile(r"\bat\s+[\w$.<>\[\] ]+\s+\(.*:\d+:\d+\)"),
    re.compile(r"node_modules[\\/]"),
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"Sequelize\w*Error|PrismaClient\w*Error|relation \".*\" does not exist", re.I),
    re.compile(r"SyntaxError: Unexpected token"),
    re.compile(r"\bECONNREFUSED\b|\bECONNRESET\b"),
    re.compile(r"/(home|app|usr|var)/[\w./-]+\.(js|ts):\d+"),
]
LOG_LINE = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}).{0,60}\b(error|warn|info|debug)\b", re.I)

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".next", "vendor"}
JS_EXT = (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")


# ==========================================
# UTILITAS UMUM
# ==========================================
class C:
    HEADER = "\033[95m"; OKBLUE = "\033[94m"; OKCYAN = "\033[96m"; OKGREEN = "\033[92m"
    WARNING = "\033[93m"; FAIL = "\033[91m"; ENDC = "\033[0m"; BOLD = "\033[1m"


def cprint(text, color=C.ENDC, end="\n"):
    print(f"{color}{text}{C.ENDC}", end=end)


def sev_color(sev):
    return {"Critical": C.FAIL, "High": C.FAIL, "Medium": C.WARNING, "Low": C.OKBLUE,
            "Informational": C.OKCYAN, "Info": C.OKCYAN, "Pass": C.OKGREEN}.get(sev, C.ENDC)


def full_url(base, path):
    return base.rstrip("/") + "/" + path.lstrip("/")


def auth_header(token):
    return {"Authorization": token if token.lower().startswith("bearer ") else f"Bearer {token}"}


def looks_like_html(resp):
    ctype = resp.headers.get("Content-Type", "").lower()
    head = resp.text[:200].lower()
    return "text/html" in ctype or "<!doctype html" in head or "<html" in head


def is_json(resp):
    try:
        resp.json()
        return True
    except ValueError:
        return False


def http(ctx, method, path, **kw):
    kw.setdefault("timeout", ctx.timeout)
    kw.setdefault("verify", ctx.verify_tls)
    kw.setdefault("allow_redirects", False)
    try:
        return ctx.session.request(method, full_url(ctx.base, path), **kw)
    except requests.exceptions.RequestException:
        return None


# --- hasil tes ---
def new(cat, name, vector):
    return {"cat": cat, "test": name, "mode": "", "status": "PASS", "vector": vector,
            "score": None, "severity": "Pass", "findings": [], "evidence": []}


def fail(r, msg, vector=None):
    r["status"] = "FAIL"
    r["findings"].append(msg)
    if vector:
        cur = cvss31(r["vector"]) if r.get("_set") else -1
        if cvss31(vector) >= cur:
            r["vector"] = vector
        r["_set"] = True


def info(r, msg):
    if r["status"] == "PASS":
        r["status"] = "INFO"
    r["findings"].append(msg)


def finalize(r):
    r.pop("_set", None)
    if r["status"] == "FAIL":
        r["score"] = cvss31(r["vector"])
        r["severity"] = cvss_label(r["score"])
    elif r["status"] == "INFO":
        r["severity"] = "Info"
        r["vector"] = None
    else:
        r["vector"] = None
    return r


# --- file proyek ---
def iter_files(root, extensions=None, names=None, prefix=None):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if (names and fn in names) or (prefix and fn.startswith(prefix)) or \
               (extensions and fn.lower().endswith(extensions)):
                yield os.path.join(dirpath, fn)


def read_text(path, limit=1_500_000):
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read(limit)
    except OSError:
        return ""


def grep(project, exts, patterns, skip_tests=True):
    """patterns: [(label, compiled_regex)] -> [(label, 'file:line', match)]"""
    hits = []
    for f in iter_files(project, extensions=exts):
        low = f.lower()
        if skip_tests and re.search(r"(\.test\.|\.spec\.|[\\/]tests?[\\/]|__tests__|\.min\.)", low):
            continue
        txt = read_text(f)
        for label, pat in patterns:
            for m in pat.finditer(txt):
                line = txt.count("\n", 0, m.start()) + 1
                hits.append((label, f"{os.path.relpath(f, project)}:{line}", m))
    return hits


def hit_evidence(hits, per_label=3):
    g = {}
    for label, loc, _ in hits:
        g.setdefault(label, []).append(loc)
    return [f"{lab}: {len(locs)} lokasi (mis. {', '.join(locs[:per_label])})" for lab, locs in g.items()]


def load_pkgs(project):
    out = []
    for pj in iter_files(project, names={"package.json"}):
        try:
            out.append((pj, json.loads(read_text(pj))))
        except json.JSONDecodeError:
            continue
    return out


def all_deps(pkg):
    return {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}


def project_deps(project):
    deps = {}
    for _, d in load_pkgs(project):
        deps.update(all_deps(d))
    return deps


def docker_logs(container, since_seconds):
    try:
        p = subprocess.run(["docker", "logs", "--since", f"{since_seconds}s", container],
                           capture_output=True, text=True, timeout=20)
        return None if p.returncode != 0 else (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return None


def db_count(db_url, table):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table):
        return None
    try:
        p = subprocess.run(["psql", db_url, "-t", "-A", "-c", f"SELECT count(*) FROM {table};"],
                           capture_output=True, text=True, timeout=15)
        return None if p.returncode != 0 else int(p.stdout.strip())
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def cred_body(user, pw):
    return {"username": user, "email": f"{user}@example.com", "password": pw}


def find_login(ctx):
    if hasattr(ctx, "_login"):
        return ctx._login
    ctx._login = None
    for p in ([ctx.args.login_path] if ctx.args.login_path else LOGIN_PATHS):
        r = http(ctx, "POST", p, json=cred_body("a09_probe", "wrong-password-a09"))
        if r is not None and r.status_code not in (404, 405) and not looks_like_html(r):
            ctx._login = p
            break
    return ctx._login


# ==========================================
# A01 - Broken Access Control
# ==========================================
def t_a01_unauth(ctx):
    r = new("A01", "Akses tanpa autentikasi", V["A01_UNAUTH_LO"])
    custom = ctx.args.protected_path
    hits = []
    for p in (custom or DEFAULT_PROTECTED):
        resp = http(ctx, "GET", p)
        if resp is None or resp.status_code != 200 or looks_like_html(resp) or not is_json(resp):
            continue
        if len(resp.content) > 2:
            hits.append(f"{p} -> HTTP 200 JSON {len(resp.content)} bytes tanpa kredensial")
    if hits:
        fail(r, f"{len(hits)} endpoint mengembalikan data tanpa autentikasi", V["A01_UNAUTH_HI"] if custom else V["A01_UNAUTH_LO"])
        r["evidence"] += hits
        if not custom:
            r["evidence"].append("Verifikasi manual: endpoint ini mungkin memang publik (gunakan --protected-path untuk yang pasti terlindungi).")
    else:
        r["evidence"].append(f"{len(custom or DEFAULT_PROTECTED)} path diuji, tidak ada kebocoran data tanpa auth")
    return finalize(r)


def t_a01_idor(ctx):
    a = ctx.args
    r = new("A01", "IDOR/BOLA lintas tenant", V["A01_IDOR"])
    if not (a.token_a and a.idor_path and a.id_a and a.id_b):
        info(r, "Dilewati: butuh --token-a, --idor-path '/api/x/{id}', --id-a (milik A), --id-b (milik tenant lain)")
        return finalize(r)
    own = http(ctx, "GET", a.idor_path.replace("{id}", str(a.id_a)), headers=auth_header(a.token_a))
    if own is None or own.status_code != 200:
        info(r, f"Baseline gagal: token-a tidak bisa membaca id-a (HTTP {own.status_code if own else 'n/a'})")
        return finalize(r)
    cross = http(ctx, "GET", a.idor_path.replace("{id}", str(a.id_b)), headers=auth_header(a.token_a))
    r["evidence"].append(f"token-a -> id-a: HTTP 200 | token-a -> id-b: HTTP {cross.status_code if cross else 'n/a'}")
    if cross is not None and cross.status_code == 200 and not looks_like_html(cross):
        fail(r, "Token tenant A dapat membaca resource tenant lain (IDOR/BOLA)")
    if a.token_b:
        rev = http(ctx, "GET", a.idor_path.replace("{id}", str(a.id_a)), headers=auth_header(a.token_b))
        r["evidence"].append(f"token-b -> id-a: HTTP {rev.status_code if rev else 'n/a'}")
        if rev is not None and rev.status_code == 200 and not looks_like_html(rev):
            fail(r, "Token tenant B dapat membaca resource tenant A")
    return finalize(r)


def t_a01_priv(ctx):
    a = ctx.args
    r = new("A01", "Privilege Escalation (vertikal)", V["A01_PRIV"])
    if not (a.token_a and a.admin_path):
        info(r, "Dilewati: butuh --token-a (user biasa) dan --admin-path (endpoint khusus admin)")
        return finalize(r)
    resp = http(ctx, "GET", a.admin_path, headers=auth_header(a.token_a))
    r["evidence"].append(f"user biasa -> {a.admin_path}: HTTP {resp.status_code if resp else 'n/a'}")
    if resp is not None and resp.status_code == 200 and not looks_like_html(resp):
        fail(r, "User biasa dapat mengakses endpoint admin")
    return finalize(r)


# ==========================================
# A02 - Security Misconfiguration
# ==========================================
def t_a02_headers(ctx):
    r = new("A02", "Header keamanan & CORS", V["A02"])
    resp = http(ctx, "GET", "/")
    if resp is None:
        info(r, "Target tidak dapat dijangkau")
        return finalize(r)
    h = {k.lower(): v for k, v in resp.headers.items()}
    missing = []
    if ctx.base.startswith("https") and "strict-transport-security" not in h:
        missing.append("Strict-Transport-Security")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        missing.append("X-Content-Type-Options: nosniff")
    csp = h.get("content-security-policy", "")
    if not csp:
        missing.append("Content-Security-Policy")
    if "x-frame-options" not in h and "frame-ancestors" not in csp:
        missing.append("Proteksi clickjacking (X-Frame-Options / frame-ancestors)")
    if missing:
        fail(r, "Header hilang: " + "; ".join(missing), V["A02"])
    for leak in ("x-powered-by", "server"):
        if leak in h and re.search(r"\d", h[leak]):
            fail(r, f"Header {leak} membocorkan versi: {h[leak]}", V["A02"])
    evil = "https://evil.example"
    cr = http(ctx, "GET", "/api/", headers={"Origin": evil}) or resp
    acao = cr.headers.get("Access-Control-Allow-Origin", "")
    acac = cr.headers.get("Access-Control-Allow-Credentials", "").lower()
    if acao == evil and acac == "true":
        fail(r, "CORS memantulkan Origin sembarang dengan credentials=true", V["A02_CORS"])
    elif acao == "*" and acac == "true":
        fail(r, "CORS '*' dengan credentials=true", V["A02_CORS"])
    if r["status"] == "PASS":
        r["evidence"].append("HSTS, nosniff, CSP, anti-clickjacking ada; CORS tidak memantulkan origin asing")
    return finalize(r)


def t_a02_exposed_files(ctx):
    r = new("A02", "File sensitif terekspos", V["A02_FILES"])
    try:
        base404 = http(ctx, "GET", f"/zz-{uuid.uuid4().hex[:8]}")
    except Exception:
        base404 = None
    exposed = []
    for path, pat in EXPOSED_FILES.items():
        resp = http(ctx, "GET", path)
        if resp is None or resp.status_code != 200 or len(resp.content) < 5:
            continue
        if looks_like_html(resp) or (base404 is not None and base404.status_code == 200 and resp.text == base404.text):
            continue
        if pat.search(resp.text[:20000]):
            exposed.append(f"{path} (HTTP 200, {len(resp.content)} bytes, isi cocok pola)")
    if exposed:
        fail(r, f"{len(exposed)} file sensitif dapat diunduh publik")
        r["evidence"] += exposed
    else:
        r["evidence"].append(f"{len(EXPOSED_FILES)} path diuji, tidak ada yang terekspos")
    return finalize(r)


def t_a02_nginx(ctx):
    r = new("A02", "Konfigurasi Nginx & Docker (kode)", V["A02"])
    p = ctx.project
    confs = [f for f in iter_files(p, extensions=(".conf",)) if "nginx" in f.lower() or "conf.d" in f.lower()]
    if not confs:
        info(r, "Tidak ada file .conf Nginx ditemukan di proyek")
        return finalize(r)
    text = "\n".join(read_text(f) for f in confs)
    issues = []
    if not re.search(r"server_tokens\s+off", text):
        issues.append("server_tokens off tidak diset (versi Nginx bocor)")
    if not re.search(r"location\s+~\*?\s+[^{]*\\\.", text):
        issues.append("Tidak ada rule yang memblokir dotfile (/.git, /.env)")
    if "add_header" not in text:
        issues.append("Tidak ada add_header (header keamanan tidak diset di Nginx)")
    if not re.search(r"listen\s+443|ssl_certificate", text):
        issues.append("Tidak ada konfigurasi TLS (listen 443/ssl_certificate)")
    # docker-compose: port DB terbuka ke host
    for f in iter_files(p, names={"docker-compose.yml", "docker-compose.yaml"}):
        if re.search(r"-\s*['\"]?(0\.0\.0\.0:)?5432:5432", read_text(f)):
            issues.append(f"{os.path.basename(f)}: port PostgreSQL 5432 dipetakan ke host")
    r["evidence"].append("File diperiksa: " + ", ".join(os.path.basename(c) for c in confs[:5]))
    if issues:
        fail(r, "; ".join(issues), V["A02"])
    return finalize(r)


# ==========================================
# A03 - Software Supply Chain Failures
# ==========================================
def t_a03_supply(ctx):
    r = new("A03", "Supply chain: dependency (kode)", V["A03_HYGIENE"])
    p = ctx.project
    pkgs = load_pkgs(p)
    if not pkgs:
        info(r, "Tidak ada package.json ditemukan")
        return finalize(r)
    lock_dirs, nolock = [], []
    for pj, data in pkgs:
        d = os.path.dirname(pj)
        if any(os.path.isfile(os.path.join(d, l)) for l in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
            lock_dirs.append(d)
        else:
            nolock.append(os.path.relpath(d, p) or ".")
        for name, ver in all_deps(data).items():
            if ver.strip() in ("*", "latest", "") or re.match(r"^(git|http|github:)", ver.strip()):
                fail(r, f"Dependency tidak ter-pin/berasal dari sumber non-registry: {name}@{ver}", V["A03_HYGIENE"])
        for hook in ("preinstall", "postinstall"):
            if hook in data.get("scripts", {}):
                r["evidence"].append(f"{os.path.relpath(pj, p)} punya script {hook} (tinjau isinya)")
    if nolock:
        fail(r, "Tanpa lockfile: " + ", ".join(nolock), V["A03_HYGIENE"])

    if ctx.args.no_audit:
        r["evidence"].append("npm audit dilewati (--no-audit)")
    elif not shutil.which("npm"):
        r["evidence"].append("npm tidak terpasang; npm audit dilewati")
    else:
        for d in [x for x in lock_dirs if os.path.isfile(os.path.join(x, "package-lock.json"))][:3]:
            try:
                out = subprocess.run(["npm", "audit", "--json"], cwd=d, capture_output=True, text=True, timeout=120)
                vul = json.loads(out.stdout or "{}").get("metadata", {}).get("vulnerabilities")
            except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
                vul = None
            rel = os.path.relpath(d, p) or "."
            if not vul:
                r["evidence"].append(f"npm audit gagal di {rel} (butuh jaringan ke registry?)")
                continue
            r["evidence"].append(f"npm audit {rel}: " + ", ".join(f"{k}={vul.get(k, 0)}" for k in ("critical", "high", "moderate", "low")))
            if vul.get("critical", 0):
                fail(r, f"{vul['critical']} kerentanan CRITICAL di {rel}", V["A03_CRIT"])
            elif vul.get("high", 0):
                fail(r, f"{vul['high']} kerentanan HIGH di {rel}", V["A03_HIGH"])
    return finalize(r)


# ==========================================
# A04 - Cryptographic Failures
# ==========================================
def t_a04_transport(ctx):
    r = new("A04", "Transport & sertifikat TLS", V["A04_TLS"])
    if ctx.base.startswith("http://"):
        fail(r, "Target memakai HTTP (tanpa enkripsi)", V["A04_TLS"])
        return finalize(r)
    try:
        requests.get(ctx.base, timeout=ctx.timeout, verify=True)
        r["evidence"].append("Sertifikat TLS valid & dipercaya")
    except requests.exceptions.SSLError as e:
        fail(r, f"Validasi sertifikat TLS gagal: {str(e)[:120]}", V["A04_TLS"])
    except requests.exceptions.RequestException as e:
        info(r, f"Tidak dapat memeriksa TLS: {e.__class__.__name__}")
    http_url = "http://" + ctx.base.split("://", 1)[1]
    try:
        h = requests.get(http_url, timeout=ctx.timeout, allow_redirects=False)
        loc = h.headers.get("Location", "")
        if h.status_code == 200 or not loc.startswith("https://"):
            fail(r, "Versi HTTP tidak mengalihkan ke HTTPS", V["A04_TLS"])
    except requests.exceptions.RequestException:
        pass
    return finalize(r)


def t_a04_static(ctx):
    r = new("A04", "Kriptografi & rahasia (kode)", V["A04"])
    p = ctx.project
    weak = grep(p, JS_EXT, [
        ("Hash lemah md5/sha1", re.compile(r"createHash\(\s*['\"](md5|sha1)['\"]")),
        ("Library md5", re.compile(r"require\(\s*['\"]md5['\"]\s*\)")),
    ])
    if weak:
        fail(r, "Algoritma hash lemah dipakai (verifikasi apakah untuk password)", V["A04"])
        r["evidence"] += hit_evidence(weak)

    rounds = grep(p, JS_EXT, [("bcrypt rounds rendah", re.compile(r"bcrypt\w*\.(?:hash|hashSync)\([^,()]+,\s*(\d+)\s*\)"))])
    low = [h for h in rounds if int(h[2].group(1)) < 10]
    if low:
        fail(r, "bcrypt salt rounds < 10", V["A04"])
        r["evidence"] += hit_evidence(low)

    deps = project_deps(p)
    has_lib = any(x in deps for x in ("bcrypt", "bcryptjs", "argon2", "scrypt"))
    has_native = grep(p, JS_EXT, [("kdf", re.compile(r"pbkdf2|scrypt", re.I))])
    mentions_pw = grep(p, JS_EXT, [("pw", re.compile(r"\bpassword\b", re.I))])
    if mentions_pw and not has_lib and not has_native:
        fail(r, "Kode memakai password tetapi tidak ada bcrypt/argon2/scrypt/pbkdf2", V["A04"])

    secrets = grep(p, JS_EXT + (".json", ".yml", ".yaml"), [
        ("Rahasia hardcoded", re.compile(r"(?i)\b(jwt[_-]?secret|secret[_-]?key|api[_-]?key|db[_-]?pass(?:word)?|private[_-]?key)\w*\s*[:=]\s*['\"][^'\"\s$]{6,}['\"]")),
        ("Fallback rahasia di env", re.compile(r"process\.env\.\w*(SECRET|KEY|PASSWORD)\w*\s*\|\|\s*['\"]")),
    ])
    secrets = [h for h in secrets if "package" not in h[1] and "lock" not in h[1]]
    if secrets:
        fail(r, "Indikasi rahasia hardcoded / fallback default", V["A04_SECRET"])
        r["evidence"] += hit_evidence(secrets)

    envs = [f for f in iter_files(p, names={".env"})]
    gi = read_text(os.path.join(p, ".gitignore"))
    if envs and not re.search(r"^\s*\.env\b", gi, re.M):
        fail(r, ".env ada di proyek tetapi tidak di-ignore oleh .gitignore root", V["A04_SECRET"])
        r["evidence"].append("File: " + ", ".join(os.path.relpath(e, p) for e in envs[:3]))

    tls_off = grep(p, JS_EXT, [("TLS verifikasi dimatikan", re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"))])
    if tls_off:
        fail(r, "Verifikasi sertifikat TLS dimatikan di kode", V["A04_TLS"])
        r["evidence"] += hit_evidence(tls_off)
    return finalize(r)


# ==========================================
# A05 - Injection
# ==========================================
def _probe_targets(ctx):
    cands = list(ctx.args.probe_path or []) + DEFAULT_PROBE
    out = []
    hdr = auth_header(ctx.args.token_a) if ctx.args.token_a else {}
    for p in cands:
        resp = http(ctx, "GET", p + "a09test", headers=hdr)
        if resp is not None and resp.status_code not in (404, 405) and not looks_like_html(resp):
            out.append((p, resp, hdr))
    return out


def t_a05_sqli(ctx):
    r = new("A05", "SQL Injection (probe error-based)", V["A05_SQLI"])
    targets = _probe_targets(ctx)
    if not targets:
        info(r, "Tidak ada endpoint dengan parameter pencarian yang ditemukan; gunakan --probe-path '/api/x?search='")
        return finalize(r)
    for p, base, hdr in targets:
        for payload in ("'", "\"", "')--"):
            resp = http(ctx, "GET", p + quote(payload), headers=hdr)
            if resp is None:
                continue
            if SQL_ERRORS.search(resp.text) and not SQL_ERRORS.search(base.text):
                fail(r, f"Pesan error database muncul pada {p} dengan payload {payload!r}")
                r["evidence"].append(f"{p}{payload} -> HTTP {resp.status_code}, signature SQL error terdeteksi")
                break
            if resp.status_code >= 500 and base.status_code < 500:
                fail(r, f"Payload {payload!r} memicu HTTP {resp.status_code} pada {p} (indikasi query rusak)")
                r["evidence"].append("Perlu verifikasi manual; kemungkinan injection")
                break
    if r["status"] == "PASS":
        r["evidence"].append(f"{len(targets)} endpoint diprobe, tidak ada indikasi injection")
    return finalize(r)


def t_a05_xss(ctx):
    r = new("A05", "Reflected XSS (probe refleksi)", V["A05_XSS"])
    tag = f"a09{uuid.uuid4().hex[:6]}"
    canary = f"\"><{tag}>"
    targets = _probe_targets(ctx) or [("/?q=", None, {})]
    for p, _, hdr in targets:
        resp = http(ctx, "GET", p + quote(canary), headers=hdr)
        if resp is None or f"<{tag}>" not in resp.text:
            continue
        if "text/html" in resp.headers.get("Content-Type", "").lower():
            fail(r, f"Input dipantulkan tanpa encoding di HTML pada {p}")
            r["evidence"].append(f"{p} -> canary <{tag}> muncul mentah di respons text/html")
        else:
            r["evidence"].append(f"{p}: canary dipantulkan di respons non-HTML (aman selama klien tidak memakai innerHTML)")
    if r["status"] == "PASS" and not r["evidence"]:
        r["evidence"].append("Tidak ada refleksi input mentah terdeteksi")
    return finalize(r)


def t_a05_static(ctx):
    r = new("A05", "Injection sink (kode)", V["A05_POTENTIAL"])
    p = ctx.project
    hits = grep(p, JS_EXT, [
        ("SQL template literal berinterpolasi", re.compile(r"\.(?:query|raw)\(\s*`[^`]*\$\{")),
        ("SQL konkatenasi string", re.compile(r"\.query\(\s*['\"][^'\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*['\"]\s*\+", re.I)),
        ("Prisma/Sequelize raw tidak aman", re.compile(r"\$(?:queryRawUnsafe|executeRawUnsafe)|sequelize\.query\(\s*`[^`]*\$\{")),
        ("eval / new Function", re.compile(r"(?<![\w.])eval\(|new Function\(")),
        ("child_process exec berinterpolasi", re.compile(r"\bexec(?:Sync)?\(\s*`[^`]*\$\{")),
        ("NoSQL $where", re.compile(r"\$where")),
    ])
    xss = grep(p, JS_EXT + (".html", ".vue"), [
        ("innerHTML/dangerouslySetInnerHTML/v-html", re.compile(r"\.innerHTML\s*=|dangerouslySetInnerHTML|v-html")),
    ])
    if hits:
        fail(r, "Sink injection berpotensi tidak aman (perlu ditinjau manual)", V["A05_POTENTIAL"])
        r["evidence"] += hit_evidence(hits)
    if xss:
        fail(r, "Penggunaan sink HTML mentah di frontend", V["A05_XSS"])
        r["evidence"] += hit_evidence(xss)
    return finalize(r)


# ==========================================
# A06 - Insecure Design
# ==========================================
def t_a06_static(ctx):
    r = new("A06", "Kontrol desain (kode, heuristik)", V["A06"])
    p = ctx.project
    deps = project_deps(p)
    rl = [d for d in ("express-rate-limit", "rate-limiter-flexible", "express-slow-down") if d in deps]
    val = [d for d in ("joi", "zod", "express-validator", "yup", "ajv", "class-validator", "celebrate") if d in deps]
    if not rl:
        fail(r, "Tidak ada library rate limiting di dependency", V["A06"])
    if not val:
        fail(r, "Tidak ada library validasi skema input di dependency", V["A06"])
    if "helmet" not in deps:
        r["evidence"].append("helmet tidak terpasang (lihat juga A02)")
    r["evidence"].append(f"Rate limit: {rl or 'tidak ada'} | Validasi: {val or 'tidak ada'}")

    # Heuristik multi-tenant: query SQL yang tidak menyebut tenant
    sql_pat = re.compile(r"(?is)(`[^`]*`|\"[^\"\n]*\"|'[^'\n]*')")
    kw = re.compile(r"(?is)\b(select\b.+?\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b")
    total = notenant = 0
    uses_tenant = False
    for f in iter_files(p, extensions=JS_EXT):
        if re.search(r"(\.test\.|\.spec\.|[\\/]tests?[\\/]|migration)", f.lower()):
            continue
        txt = read_text(f)
        uses_tenant = uses_tenant or "tenant" in txt.lower()
        for m in sql_pat.finditer(txt):
            s = m.group(0)
            if kw.search(s):
                total += 1
                if "tenant" not in s.lower():
                    notenant += 1
    if uses_tenant and total:
        r["evidence"].append(f"Heuristik multi-tenant: {notenant} dari {total} query SQL tidak menyebut tenant (tinjau manual; sebagian wajar, mis. tabel global)")
    r["evidence"].append("Catatan: A06 sebagian besar butuh threat modelling & review logika bisnis manual.")
    return finalize(r)


# ==========================================
# A07 - Authentication Failures
# ==========================================
def t_a07_brute(ctx):
    r = new("A07", "Brute-force login", V["A07_BRUTE"])
    path = find_login(ctx)
    if not path:
        info(r, "Endpoint login tidak ditemukan (gunakan --login-path)")
        return finalize(r)
    statuses, blocked, why = [], None, ""
    for i in range(ctx.args.attempts):
        resp = http(ctx, "POST", path, json=cred_body("a09_probe", f"wrong-{i}"))
        if resp is None:
            continue
        statuses.append(resp.status_code)
        body = resp.text.lower()
        if resp.status_code in (429, 503, 423):
            blocked, why = i + 1, f"HTTP {resp.status_code}"
        elif statuses[0] in (400, 401) and resp.status_code == 403:
            blocked, why = i + 1, "401 berubah menjadi 403"
        elif any(k in body for k in ("too many", "locked", "terkunci", "blocked", "terlalu banyak")):
            blocked, why = i + 1, "pesan blokir"
        if blocked:
            break
    r["evidence"] += [f"Endpoint: {path}", f"Status berurutan: {statuses}"]
    if blocked:
        r["evidence"].append(f"Pembatasan aktif setelah {blocked} percobaan ({why})")
    else:
        fail(r, f"{len(statuses)} login gagal beruntun tidak dibatasi", V["A07_BRUTE"])
    return finalize(r)


def _b64json(seg):
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def t_a07_jwt(ctx):
    r = new("A07", "Kualitas token JWT", V["A07_TOKEN"])
    tok = ctx.args.token_a
    if not tok:
        info(r, "Dilewati: butuh --token-a (JWT)")
        return finalize(r)
    tok = tok.split(" ", 1)[-1]
    try:
        h, pl, _ = tok.split(".")
        head, payload = _b64json(h), _b64json(pl)
    except Exception:
        info(r, "Token-a bukan JWT yang dapat didekode")
        return finalize(r)
    r["evidence"].append(f"alg={head.get('alg')} klaim={sorted(payload.keys())}")
    if str(head.get("alg", "")).lower() == "none":
        fail(r, "Token memakai alg=none", V["A07_NONE"])
    if "exp" not in payload:
        fail(r, "Token tanpa klaim exp (tidak pernah kedaluwarsa)", V["A07_TOKEN"])
    elif "iat" in payload and payload["exp"] - payload["iat"] > 7 * 86400:
        fail(r, f"Masa berlaku token {(payload['exp'] - payload['iat']) // 86400} hari (terlalu panjang)", V["A07_TOKEN"])
    for k in ("password", "passwd", "hash", "secret"):
        if k in payload:
            fail(r, f"Payload JWT memuat data sensitif: {k}", V["A07_TOKEN"])
    return finalize(r)


def t_a07_static(ctx):
    r = new("A07", "Konfigurasi autentikasi (kode)", V["A07_TOKEN"])
    p = ctx.project
    hits = grep(p, JS_EXT, [
        ("jwt.sign tanpa expiresIn", re.compile(r"jwt\.sign\((?:(?!expiresIn).){0,250}?\)", re.S)),
        ("jwt.verify tanpa algorithms", re.compile(r"jwt\.verify\((?:(?!algorithms).){0,200}?\)", re.S)),
        ("Cookie httpOnly/secure = false", re.compile(r"(?:httpOnly|secure)\s*:\s*false")),
    ])
    none_alg = grep(p, JS_EXT, [("Algoritma 'none'", re.compile(r"algorithms?\s*:\s*\[?\s*['\"]none['\"]", re.I))])
    # jwt.sign yang punya expiresIn tidak ikut: pola di atas hanya cocok bila tidak ada expiresIn dalam jendela
    if hits:
        fail(r, "Konfigurasi token/cookie lemah", V["A07_TOKEN"])
        r["evidence"] += hit_evidence(hits)
    if none_alg:
        fail(r, "JWT dikonfigurasi menerima alg none", V["A07_NONE"])
        r["evidence"] += hit_evidence(none_alg)
    return finalize(r)


# ==========================================
# A08 - Software or Data Integrity Failures
# ==========================================
def t_a08_sri(ctx):
    r = new("A08", "Subresource Integrity (SRI)", V["A08"])
    resp = http(ctx, "GET", "/")
    if resp is None or not looks_like_html(resp):
        info(r, "Halaman utama bukan HTML / tidak dapat dijangkau")
        return finalize(r)
    host = urlparse(ctx.base).netloc
    bad = []
    for m in re.finditer(r"<(script|link)\b[^>]*>", resp.text, re.I):
        tag = m.group(0)
        if m.group(1).lower() == "link" and "stylesheet" not in tag.lower():
            continue
        u = re.search(r"(?:src|href)=[\"']((?:https?:)?//[^\"']+)", tag, re.I)
        if not u:
            continue
        netloc = urlparse(u.group(1) if not u.group(1).startswith("//") else "https:" + u.group(1)).netloc
        if netloc != host and "integrity=" not in tag.lower():
            bad.append(u.group(1)[:90])
    if bad:
        fail(r, f"{len(bad)} resource eksternal tanpa atribut integrity", V["A08"])
        r["evidence"] += bad[:5]
    else:
        r["evidence"].append("Tidak ada resource eksternal tanpa SRI di halaman utama")
    return finalize(r)


def t_a08_static(ctx):
    r = new("A08", "Integritas build & deserialisasi (kode)", V["A08"])
    p = ctx.project
    dock = []
    for f in iter_files(p, prefix="Dockerfile"):
        txt = read_text(f)
        rel = os.path.relpath(f, p)
        if re.search(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba)?sh", txt):
            dock.append(("Pipe-to-shell di Dockerfile", rel, V["A08_RCE"]))
        if re.search(r"^\s*ADD\s+https?://", txt, re.M):
            dock.append(("ADD dari URL remote", rel, V["A08"]))
        if re.search(r"^\s*RUN\s+.*npm\s+install(?!\s+-g)", txt, re.M):
            dock.append(("npm install (bukan npm ci) di Dockerfile", rel, V["A08"]))
        if re.search(r"^\s*FROM\s+\S+:latest|^\s*FROM\s+[^:\s]+\s*$", txt, re.M):
            dock.append(("Base image tidak ter-pin (latest/tanpa tag)", rel, V["A08"]))
    for label, rel, vec in dock:
        fail(r, f"{label}: {rel}", vec)

    for f in iter_files(p, extensions=(".yml", ".yaml")):
        if ".github" not in f.replace("\\", "/"):
            continue
        txt = read_text(f)
        rel = os.path.relpath(f, p)
        if "pull_request_target" in txt:
            fail(r, f"{rel}: memakai pull_request_target (risiko eksekusi kode dari fork)", V["A08_RCE"])
        if re.search(r"uses:\s*\S+@(main|master)\b", txt):
            fail(r, f"{rel}: GitHub Action diacu ke branch (bukan SHA/versi tetap)", V["A08"])

    des = grep(p, JS_EXT, [
        ("Deserialisasi tidak aman", re.compile(r"node-serialize|\bunserialize\(|yaml\.load\(|vm\.runIn\w+\(")),
    ])
    if des:
        fail(r, "Pola deserialisasi/eksekusi dinamis berisiko", V["A08_RCE"])
        r["evidence"] += hit_evidence(des)
    return finalize(r)


# ==========================================
# A09 - Security Logging & Alerting Failures
# ==========================================
def t_a09_exposure(ctx):
    r = new("A09", "Log terekspos publik", V["A09_LOGS"])
    base404 = http(ctx, "GET", f"/zz-{uuid.uuid4().hex[:8]}")
    exposed = []
    for path in COMMON_LOG_PATHS:
        resp = http(ctx, "GET", path)
        if resp is None or resp.status_code != 200 or len(resp.content) < 50 or looks_like_html(resp):
            continue
        if base404 is not None and base404.status_code == 200 and resp.text == base404.text:
            continue
        if LOG_LINE.search(resp.text[:5000]):
            exposed.append(f"{path} (HTTP 200, {len(resp.content)} bytes, isi mirip log)")
    if exposed:
        fail(r, f"{len(exposed)} path log terekspos")
        r["evidence"] += exposed
    else:
        r["evidence"].append(f"{len(COMMON_LOG_PATHS)} path diuji, tidak ada log terekspos")
    return finalize(r)


def t_a09_correlation(ctx):
    r = new("A09", "Korelasi log server-side", V["A09_AUDIT"])
    a = ctx.args
    if not a.container and not a.db_url:
        info(r, "Tidak dapat diverifikasi black-box; berikan --container dan/atau --db-url")
        return finalize(r)
    path = find_login(ctx)
    if not path:
        info(r, "Endpoint login tidak ditemukan, korelasi dilewati")
        return finalize(r)
    marker = f"a09marker{uuid.uuid4().hex[:10]}"
    before = db_count(a.db_url, a.audit_table) if a.db_url else None
    http(ctx, "POST", path, json=cred_body(marker, "wrong-password"), headers={"X-Request-ID": marker})
    time.sleep(2)
    checks = []
    if a.container:
        logs = docker_logs(a.container, 60)
        if logs is None:
            r["evidence"].append(f"Gagal membaca docker logs '{a.container}'")
        else:
            checks.append(("docker logs", marker in logs))
            r["evidence"].append(f"Marker di docker logs: {'DITEMUKAN' if marker in logs else 'TIDAK ADA'}")
    if a.db_url:
        after = db_count(a.db_url, a.audit_table)
        if before is None or after is None:
            r["evidence"].append("Gagal query tabel audit (psql/URL/nama tabel?)")
        else:
            checks.append(("tabel audit", after > before))
            r["evidence"].append(f"Baris {a.audit_table}: {before} -> {after}")
    if not checks:
        info(r, "Verifikasi server-side gagal dijalankan")
    elif not any(ok for _, ok in checks):
        fail(r, "Login gagal TIDAK tercatat di log maupun audit (tidak ada jejak forensik)", V["A09_AUDIT"])
    elif not all(ok for _, ok in checks):
        fail(r, "Hanya tercatat sebagian: " + ", ".join(f"{n}={'ok' if ok else 'tidak'}" for n, ok in checks), V["A09_AUDIT"])
    return finalize(r)


def t_a09_static(ctx):
    r = new("A09", "Logger & audit trail (kode)", V["A09_AUDIT"])
    p = ctx.project
    deps = project_deps(p)
    fw = [x for x in LOGGING_FRAMEWORKS if x in deps]
    logger_calls = len(grep(p, JS_EXT, [("l", re.compile(r"\blogger\.(info|warn|error|debug)\("))]))
    console_calls = len(grep(p, JS_EXT, [("c", re.compile(r"\bconsole\.(log|error|warn)\("))]))
    r["evidence"].append(f"Framework: {fw or 'tidak ada'} | logger.*: {logger_calls} | console.*: {console_calls}")
    if not fw:
        fail(r, "Tidak ada framework logging terstruktur", V["A09_AUDIT"])
    elif logger_calls == 0:
        fail(r, "Framework terpasang tetapi tidak dipanggil di kode", V["A09_AUDIT"])
    schema, code = set(), set()
    for f in iter_files(p, extensions=(".sql", ".prisma", ".js", ".ts")):
        low = read_text(f).lower()
        for k in AUDIT_KEYWORDS:
            if k in low:
                is_schema = f.lower().endswith((".sql", ".prisma")) or "migration" in f.lower() or "schema" in f.lower()
                (schema if is_schema else code).add(f"{k} ({os.path.basename(f)})")
    if not schema:
        fail(r, "Tidak ada tabel audit di skema/migration", V["A09_AUDIT"])
    elif not code:
        fail(r, "Tabel audit ada tetapi tidak ada kode yang menulis ke sana", V["A09_AUDIT"])
    r["evidence"] += sorted(schema)[:3] + sorted(code)[:3]
    r["evidence"].append("Catatan: CVSS menilai 0.0 untuk A09 (tidak ada dampak langsung); laporkan sebagai Informational.")
    return finalize(r)


# ==========================================
# A10 - Mishandling of Exceptional Conditions
# ==========================================
def t_a10_leak(ctx):
    r = new("A10", "Kebocoran detail pada error", V["A10"])
    login = ctx.args.login_path or LOGIN_PATHS[0]
    trig = [
        ("GET", f"/api/nonexistent-{uuid.uuid4().hex[:6]}", None, None),
        ("POST", login, "{invalid json", {"Content-Type": "application/json"}),
        ("POST", login, json.dumps({"username": {"$ne": None}, "password": [1, 2]}), {"Content-Type": "application/json"}),
        ("GET", "/api/users/..%2f..%2fetc%2fpasswd", None, None),
        ("GET", "/api/users/'", None, None),
    ]
    leaks, tested = [], 0
    for method, path, body, hdr in trig:
        resp = http(ctx, method, path, data=body, headers=hdr or {})
        if resp is None:
            continue
        tested += 1
        if resp.status_code < 400:
            continue
        for pat in LEAK_PATTERNS:
            m = pat.search(resp.text)
            if m:
                leaks.append(f"{method} {path} -> HTTP {resp.status_code}: '{m.group(0)[:80]}'")
                break
    if leaks:
        fail(r, f"Detail internal bocor pada {len(leaks)} respons error")
        r["evidence"] += leaks
    elif tested:
        r["evidence"].append(f"{tested} respons error diuji, tidak ada kebocoran")
    else:
        info(r, "Tidak ada request error yang berhasil diuji")
    return finalize(r)


def t_a10_failopen(ctx):
    r = new("A10", "Fail-open / 5xx pada input tak valid", V["A10_5XX"])
    tested = 0
    for p in (ctx.args.protected_path or DEFAULT_PROTECTED):
        noauth = http(ctx, "GET", p)
        if noauth is None or noauth.status_code not in (401, 403):
            continue
        tested += 1
        bad = http(ctx, "GET", p, headers={"Authorization": "Bearer not.a.valid.jwt"})
        if bad is None:
            continue
        if bad.status_code == 200:
            fail(r, f"{p}: token tidak valid diterima (fail-open)", V["A01_FAILOPEN"])
        elif bad.status_code >= 500:
            fail(r, f"{p}: token malformed memicu HTTP {bad.status_code} (exception tidak ditangani)", V["A10_5XX"])
    path = find_login(ctx)
    if path:
        big = http(ctx, "POST", path, data=json.dumps({"username": "x" * 2_000_000, "password": "y"}),
                   headers={"Content-Type": "application/json"})
        r["evidence"].append(f"Body 2MB ke {path}: HTTP {big.status_code if big else 'koneksi ditutup/timeout'}")
        if big is not None and big.status_code >= 500:
            fail(r, f"Body besar memicu HTTP {big.status_code} (seharusnya 413/400)", V["A10_5XX"])
    if not tested and not path:
        info(r, "Tidak ada endpoint terproteksi/login yang ditemukan untuk diuji")
    return finalize(r)


def t_a10_static(ctx):
    r = new("A10", "Penanganan exception (kode)", V["A10"])
    p = ctx.project
    mw = grep(p, JS_EXT, [("mw", re.compile(r"\(\s*err(?:or)?\s*,\s*req\s*,\s*res\s*,\s*next\s*\)"))])
    proc = grep(p, JS_EXT, [("proc", re.compile(r"process\.on\(\s*['\"](uncaughtException|unhandledRejection)['\"]"))])
    empty = grep(p, JS_EXT, [("Blok catch kosong", re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*\}"))])
    deps = project_deps(p)
    async_wrap = any(x in deps for x in ("express-async-errors", "express-async-handler"))
    r["evidence"].append(f"Error middleware: {len(mw)} | handler process-level: {len(proc)} | wrapper async: {'ya' if async_wrap else 'tidak'}")
    if not mw:
        fail(r, "Tidak ada error-handling middleware global (err, req, res, next)", V["A10"])
    if not proc:
        fail(r, "Tidak ada handler unhandledRejection/uncaughtException", V["A10_LOW"])
    if empty:
        fail(r, "Blok catch kosong (error ditelan tanpa log)", V["A10_LOW"])
        r["evidence"] += hit_evidence(empty)
    return finalize(r)


# ==========================================
# REGISTRASI TES
# ==========================================
TESTS = [
    ("A01", "dyn", t_a01_unauth), ("A01", "dyn", t_a01_idor), ("A01", "dyn", t_a01_priv),
    ("A02", "dyn", t_a02_headers), ("A02", "dyn", t_a02_exposed_files), ("A02", "sta", t_a02_nginx),
    ("A03", "sta", t_a03_supply),
    ("A04", "dyn", t_a04_transport), ("A04", "sta", t_a04_static),
    ("A05", "dyn", t_a05_sqli), ("A05", "dyn", t_a05_xss), ("A05", "sta", t_a05_static),
    ("A06", "sta", t_a06_static),
    ("A07", "dyn", t_a07_brute), ("A07", "dyn", t_a07_jwt), ("A07", "sta", t_a07_static),
    ("A08", "dyn", t_a08_sri), ("A08", "sta", t_a08_static),
    ("A09", "dyn", t_a09_exposure), ("A09", "dyn", t_a09_correlation), ("A09", "sta", t_a09_static),
    ("A10", "dyn", t_a10_leak), ("A10", "dyn", t_a10_failopen), ("A10", "sta", t_a10_static),
]


def display_status(r):
    if r["status"] == "PASS":
        return "PASS"
    if r["status"] == "INFO":
        return "INFO"
    return "FAIL" if r["score"] >= 4 else "WARN"


def main():
    ap = argparse.ArgumentParser(description="OWASP Top 10:2025 Tester + CVSS v3.1 (SI-MITRA-DUDIKA)")
    ap.add_argument("--target", help="Base URL untuk tes dinamis (contoh: https://staging.example.com)")
    ap.add_argument("--project", help="Path source code untuk tes statis")
    ap.add_argument("--authorized", action="store_true", help="Konfirmasi Anda berwenang menguji --target")
    ap.add_argument("--timeout", type=int, default=5)
    ap.add_argument("--only", help="Batasi kategori, mis. A01,A05")
    ap.add_argument("--json-out", help="Simpan hasil ke JSON")
    ap.add_argument("--verify-tls", action="store_true", help="Verifikasi sertifikat pada request tes (default: tidak, utk staging)")
    ap.add_argument("--attempts", type=int, default=10, help="Jumlah login gagal (A07)")
    ap.add_argument("--login-path", help="Path endpoint login (default: auto-detect)")
    ap.add_argument("--token-a", help="JWT user biasa tenant A (A01, A07)")
    ap.add_argument("--token-b", help="JWT user tenant B (opsional, uji IDOR dua arah)")
    ap.add_argument("--idor-path", help="Template path resource, mis. /api/mitra/{id}")
    ap.add_argument("--id-a", help="ID resource milik tenant A")
    ap.add_argument("--id-b", help="ID resource milik tenant lain")
    ap.add_argument("--admin-path", help="Endpoint khusus admin (uji privilege escalation)")
    ap.add_argument("--protected-path", action="append", help="Endpoint yang PASTI terlindungi (boleh berulang)")
    ap.add_argument("--probe-path", action="append", help="Endpoint dengan parameter pencarian, mis. /api/mitra?search= (boleh berulang)")
    ap.add_argument("--container", help="Nama container Docker backend (A09)")
    ap.add_argument("--db-url", help="URL PostgreSQL (A09, butuh psql)")
    ap.add_argument("--audit-table", default="audit_logs")
    ap.add_argument("--no-audit", action="store_true", help="Lewati npm audit (A03)")
    args = ap.parse_args()

    if not args.target and not args.project:
        ap.error("Minimal salah satu dari --target atau --project wajib diisi")
    if args.target and not args.authorized:
        cprint("Ditolak: tambahkan --authorized untuk mengonfirmasi Anda berwenang menguji target ini.", C.FAIL)
        sys.exit(3)
    if args.project and not os.path.isdir(args.project):
        ap.error(f"--project bukan direktori valid: {args.project}")

    ctx = argparse.Namespace()
    ctx.args = args
    ctx.base = args.target.rstrip("/") if args.target else None
    ctx.project = args.project
    ctx.timeout = args.timeout
    ctx.verify_tls = args.verify_tls
    ctx.session = requests.Session()
    ctx.session.headers.update({"User-Agent": "SIMITRADUDIKA-Top10-Tester/1.0", "Accept": "application/json"})

    only = {x.strip().upper() for x in args.only.split(",")} if args.only else None

    cprint("\n" + "=" * 96, C.HEADER)
    cprint("  OWASP Top 10:2025 - Security Tester + CVSS v3.1  (SI-MITRA-DUDIKA)", C.BOLD)
    cprint(f"  Target : {ctx.base or 'N/A (tanpa tes dinamis)'}", C.OKCYAN)
    cprint(f"  Project: {ctx.project or 'N/A (tanpa tes statis)'}", C.OKCYAN)
    cprint("=" * 96 + "\n", C.HEADER)

    results = []
    for cat, mode, fn in TESTS:
        if only and cat not in only:
            continue
        if (mode == "dyn" and not ctx.base) or (mode == "sta" and not ctx.project):
            continue
        try:
            res = fn(ctx)
        except Exception as e:  # satu tes rusak tidak boleh menghentikan semuanya
            res = finalize(new(cat, fn.__name__, V["A10"]))
            res["status"], res["severity"] = "INFO", "Info"
            res["findings"].append(f"Tes gagal dijalankan: {e.__class__.__name__}: {e}")
        res["mode"] = "dinamis" if mode == "dyn" else "statis"
        results.append(res)

    skipped = []
    if not ctx.base:
        skipped.append("dinamis (tanpa --target)")
    if not ctx.project:
        skipped.append("statis (tanpa --project)")
    if skipped:
        cprint("Dilewati: tes " + " & ".join(skipped) + "\n", C.WARNING)

    cprint(f"{'ID':<5}{'Test Case':<42}{'Mode':<9}{'Status':<8}{'Skor':>5}  {'Severity':<14}", C.BOLD)
    cprint("-" * 96)
    for r in results:
        c = sev_color(r["severity"])
        score = f"{r['score']:.1f}" if r["score"] is not None else "-"
        cprint(f"{r['cat']:<5}{r['test']:<42}{r['mode']:<9}", end="")
        cprint(f"{display_status(r):<8}{score:>5}  {r['severity']:<14}", c)
    cprint("-" * 96)

    summary = {}
    for r in results:
        summary[r["severity"]] = summary.get(r["severity"], 0) + 1
    order = ["Critical", "High", "Medium", "Low", "Informational", "Info", "Pass"]
    cprint("Ringkasan: " + " | ".join(f"{k}={summary.get(k, 0)}" for k in order) + "\n", C.BOLD)

    cprint("Detail Temuan:", C.BOLD)
    cprint("=" * 96)
    for r in results:
        if r["status"] == "PASS":
            continue
        c = sev_color(r["severity"])
        head = f"[{r['severity'].upper()}] {r['cat']} {CATEGORIES[r['cat']]} - {r['test']}"
        cprint("\n" + head, c)
        if r["score"] is not None:
            cprint(f"  CVSS {r['score']:.1f} ({r['severity']})  {r['vector']}", c)
        for f in r["findings"]:
            cprint(f"  -> {f}", C.WARNING)
        for ev in r["evidence"]:
            cprint(f"     {ev}", C.OKBLUE)

    cprint("\nRekomendasi (kategori yang bermasalah):", C.BOLD)
    cprint("=" * 96)
    seen = []
    for r in results:
        if r["status"] == "FAIL" and r["cat"] not in seen:
            seen.append(r["cat"])
    if seen:
        for cat in sorted(seen):
            cprint(f"{cat} {CATEGORIES[cat]}: {REKOMENDASI[cat]}", C.OKGREEN)
    else:
        cprint("Tidak ada temuan FAIL pada tes yang dijalankan.", C.OKGREEN)
    if any(r["status"] == "INFO" for r in results):
        cprint("Catatan: tes berstatus INFO belum terverifikasi; lengkapi opsi (--token-a, --idor-path, --container, dll).", C.OKCYAN)
    cprint("Catatan: skor CVSS adalah estimasi skenario terburuk per vektor; validasi dampak nyata sebelum pelaporan final.", C.OKCYAN)
    cprint("\n" + "=" * 96 + "\n", C.HEADER)

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump({"target": ctx.base, "project": ctx.project, "summary": summary, "results": results},
                      f, indent=2, ensure_ascii=False)
        cprint(f"Hasil disimpan ke {args.json_out}", C.OKCYAN)

    top = max([r["score"] for r in results if r["score"] is not None] or [0])
    sys.exit(2 if top >= 9 else 1 if top >= 7 else 0)


if __name__ == "__main__":
    main()
