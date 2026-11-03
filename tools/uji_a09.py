#!/usr/bin/env python3
"""
uji_a09.py - OWASP A09:2021 Security Logging & Monitoring Tester (v2)
Untuk arsitektur SIMITRADUDIKA (Node.js + PostgreSQL + Nginx + Docker)

PERINGATAN: Script ini mengirim request login gagal berulang dan request
malformed. Gunakan HANYA pada sistem milik sendiri / staging yang sudah
diizinkan. Wajib menyertakan flag --authorized.

Contoh:
    python3 uji_a09.py --authorized \
        --target https://staging.example.com \
        --project /home/bissmillah/si-mitra-dudika \
        --container simitra-backend \
        --db-url postgresql://user:pass@localhost:5432/simitra \
        --audit-table audit_logs

Tes dinamis (black-box) hanya melihat apa yang tampak dari luar. Untuk
membuktikan event BENAR-BENAR tercatat, berikan --container dan/atau --db-url
agar script bisa mengkorelasikan request dengan isi log/tabel audit.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# KONFIGURASI
# ==========================================
COMMON_LOG_PATHS = [
    "/logs/", "/log/", "/debug/", "/admin/logs", "/api/logs",
    "/system/logs", "/app/logs", "/server.log", "/app.log",
    "/error.log", "/access.log", "/logs/app.log", "/logs/error.log",
    "/npm-debug.log", "/.pm2/logs/",
]

LOGIN_PATHS = ["/api/auth/login", "/api/login", "/auth/login", "/login"]

LOGGING_FRAMEWORKS = [
    "winston", "morgan", "pino", "bunyan", "log4js",
    "express-winston", "pino-http", "winston-daily-rotate-file",
    "rotating-file-stream",
]

AUDIT_KEYWORDS = [
    "audit_log", "audit_logs", "audit_trail", "activity_log",
    "activity_logs", "user_action", "event_log", "change_history",
]

SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".next", "vendor"}

# Pola stack trace / kebocoran internal yang spesifik (bukan sekadar kata "error")
LEAK_PATTERNS = [
    re.compile(r"\bat\s+[\w$.<>\[\] ]+\s+\(.*:\d+:\d+\)"),   # at fn (file.js:10:5)
    re.compile(r"node_modules[\\/]"),
    re.compile(r"Traceback \(most recent call last\)"),
    re.compile(r"Sequelize\w*Error|PrismaClient\w*Error|error: relation \".*\" does not exist", re.I),
    re.compile(r"SyntaxError: Unexpected token"),
    re.compile(r"\bECONNREFUSED\b|\bECONNRESET\b"),
    re.compile(r"/(home|app|usr|var)/[\w./-]+\.(js|ts):\d+"),  # path file internal
]

# Ciri isi file log: timestamp + level
LOG_LINE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}).{0,60}\b(error|warn|info|debug)\b",
    re.I,
)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info", "Pass"]


# ==========================================
# UTILITAS
# ==========================================
class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


def cprint(text, color=Colors.ENDC, end="\n"):
    print(f"{color}{text}{Colors.ENDC}", end=end)


def severity_color(sev):
    return {
        "Critical": Colors.FAIL, "High": Colors.FAIL,
        "Medium": Colors.WARNING, "Low": Colors.OKBLUE,
        "Info": Colors.OKCYAN, "Pass": Colors.OKGREEN,
    }.get(sev, Colors.ENDC)


def new_result(name, description):
    return {"test": name, "description": description,
            "severity": "Pass", "findings": [], "evidence": []}


def full_url(base, path):
    """Gabungkan base + path tanpa membuang sub-path (mis. https://host/app)."""
    return base.rstrip("/") + "/" + path.lstrip("/")


def iter_files(root, extensions=None, names=None):
    """Telusuri file proyek sambil melewati node_modules dsb."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if names and fn in names:
                yield os.path.join(dirpath, fn)
            elif extensions and fn.lower().endswith(extensions):
                yield os.path.join(dirpath, fn)


def read_text(path, limit=2_000_000):
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read(limit)
    except OSError:
        return ""


def docker_logs(container, since_seconds):
    """Ambil log container Docker (stdout+stderr). Return None jika gagal."""
    try:
        p = subprocess.run(
            ["docker", "logs", "--since", f"{since_seconds}s", container],
            capture_output=True, text=True, timeout=20,
        )
        if p.returncode != 0:
            return None
        return (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return None


def db_count(db_url, table, time_col):
    """Hitung baris tabel audit via psql. Return None jika gagal."""
    for ident in (table, time_col):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", ident):
            return None
    sql = f"SELECT count(*) FROM {table};"
    try:
        p = subprocess.run(
            ["psql", db_url, "-t", "-A", "-c", sql],
            capture_output=True, text=True, timeout=15,
        )
        if p.returncode != 0:
            return None
        return int(p.stdout.strip())
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def looks_like_html(resp):
    ctype = resp.headers.get("Content-Type", "").lower()
    head = resp.text[:200].lower()
    return "text/html" in ctype or "<!doctype html" in head or "<html" in head


# ==========================================
# TES DINAMIS
# ==========================================
def find_login_endpoint(base_url, session, timeout, forced=None):
    paths = [forced] if forced else LOGIN_PATHS
    for path in paths:
        try:
            r = session.post(full_url(base_url, path),
                             json={"username": "a09_probe", "email": "a09_probe@example.com",
                                   "password": "wrong-password-a09"},
                             timeout=timeout, verify=False)
        except requests.exceptions.RequestException:
            continue
        if r.status_code not in (404, 405) and not looks_like_html(r):
            return path
    return None


def test_01_bruteforce_detection(base_url, session, timeout, login_path, attempts):
    res = new_result("Brute-force Detection",
                     "Apakah login gagal berulang memicu pembatasan/blokir?")
    path = find_login_endpoint(base_url, session, timeout, login_path)
    if not path:
        res["severity"] = "Info"
        res["findings"].append("Endpoint login tidak ditemukan (semua 404/405/HTML)")
        res["evidence"].append(f"Dicoba: {', '.join([login_path] if login_path else LOGIN_PATHS)}. "
                               "Gunakan --login-path untuk menentukan manual.")
        return res

    statuses, blocked_at, reason = [], None, ""
    for i in range(attempts):
        try:
            r = session.post(full_url(base_url, path),
                             json={"username": "a09_probe", "email": "a09_probe@example.com",
                                   "password": f"wrong-{i}"},
                             timeout=timeout, verify=False)
        except requests.exceptions.RequestException as e:
            res["evidence"].append(f"Request #{i+1} gagal: {e.__class__.__name__}")
            continue
        statuses.append(r.status_code)
        body = r.text.lower()
        if r.status_code in (429, 503, 423):
            blocked_at, reason = i + 1, f"HTTP {r.status_code}"
        elif statuses[0] in (400, 401) and r.status_code == 403:
            blocked_at, reason = i + 1, "401 berubah menjadi 403"
        elif any(k in body for k in ("too many", "locked", "terkunci", "blocked", "terlalu banyak")):
            blocked_at, reason = i + 1, "pesan blokir pada body"
        if blocked_at:
            break

    res["evidence"].append(f"Endpoint: {path}")
    res["evidence"].append(f"Status berurutan: {statuses}")
    if blocked_at:
        res["findings"].append(f"Pembatasan aktif setelah {blocked_at} percobaan ({reason})")
    else:
        res["severity"] = "High"
        res["findings"].append(f"{len(statuses)} login gagal beruntun tidak dibatasi")
    return res


def test_02_log_correlation(base_url, session, timeout, login_path,
                            container, db_url, audit_table, time_col):
    res = new_result("Log Correlation (server-side)",
                     "Apakah event login gagal benar-benar tercatat di log/DB?")
    if not container and not db_url:
        res["severity"] = "Info"
        res["findings"].append("Tidak dapat diverifikasi secara black-box")
        res["evidence"].append("Berikan --container dan/atau --db-url untuk verifikasi nyata.")
        return res

    path = find_login_endpoint(base_url, session, timeout, login_path)
    if not path:
        res["severity"] = "Info"
        res["findings"].append("Endpoint login tidak ditemukan, korelasi dilewati")
        return res

    marker = f"a09marker{uuid.uuid4().hex[:10]}"
    before = db_count(db_url, audit_table, time_col) if db_url else None

    try:
        session.post(full_url(base_url, path),
                     json={"username": marker, "email": f"{marker}@example.com",
                           "password": "wrong-password"},
                     headers={"X-Request-ID": marker},
                     timeout=timeout, verify=False)
    except requests.exceptions.RequestException as e:
        res["severity"] = "Info"
        res["findings"].append(f"Request pemicu gagal: {e.__class__.__name__}")
        return res

    time.sleep(2)  # beri waktu log flush / insert async
    checks = []

    if container:
        logs = docker_logs(container, 60)
        if logs is None:
            res["evidence"].append(f"Gagal membaca docker logs '{container}' (nama salah / tak ada izin?)")
        else:
            found = marker in logs
            checks.append(("docker logs", found))
            res["evidence"].append(f"Marker '{marker}' di docker logs: {'DITEMUKAN' if found else 'TIDAK ADA'}")

    if db_url:
        after = db_count(db_url, audit_table, time_col)
        if before is None or after is None:
            res["evidence"].append("Gagal query tabel audit (psql tidak ada / URL / nama tabel salah)")
        else:
            grew = after > before
            checks.append(("tabel audit", grew))
            res["evidence"].append(f"Baris {audit_table}: {before} -> {after}")

    if not checks:
        res["severity"] = "Info"
        res["findings"].append("Verifikasi server-side gagal dijalankan")
    elif all(ok for _, ok in checks):
        res["findings"].append("Login gagal tercatat di: " + ", ".join(n for n, _ in checks))
    elif any(ok for _, ok in checks):
        res["severity"] = "Medium"
        res["findings"].append("Tercatat sebagian: " + ", ".join(f"{n}={'ok' if ok else 'tidak'}" for n, ok in checks))
    else:
        res["severity"] = "High"
        res["findings"].append("Login gagal TIDAK tercatat di log maupun audit (tidak ada jejak forensik)")
    return res


def test_03_log_exposure(base_url, session, timeout):
    res = new_result("Log Path Exposure", "Apakah file/direktori log dapat diakses publik?")
    try:
        baseline = session.get(full_url(base_url, f"/zz-{uuid.uuid4().hex[:8]}"),
                               timeout=timeout, verify=False, allow_redirects=False)
    except requests.exceptions.RequestException as e:
        res["severity"] = "Info"
        res["findings"].append(f"Target tidak dapat dijangkau: {e.__class__.__name__}")
        return res

    exposed = []
    for path in COMMON_LOG_PATHS:
        try:
            r = session.get(full_url(base_url, path), timeout=timeout,
                            verify=False, allow_redirects=False)
        except requests.exceptions.RequestException:
            continue
        if r.status_code != 200 or len(r.content) < 50:
            continue
        if looks_like_html(r):                      # SPA fallback / halaman custom
            continue
        if baseline.status_code == 200 and r.text == baseline.text:
            continue
        if LOG_LINE.search(r.text[:5000]):
            exposed.append(f"{path} (HTTP 200, {len(r.content)} bytes, mirip isi log)")

    if exposed:
        res["severity"] = "Critical"
        res["findings"].append(f"{len(exposed)} path log terekspos")
        res["evidence"].extend(exposed)
    else:
        res["findings"].append("Tidak ada log yang terekspos")
        res["evidence"].append(f"{len(COMMON_LOG_PATHS)} path diuji, baseline 404 = HTTP {baseline.status_code}")
    return res


def test_04_error_handling(base_url, session, timeout, login_path):
    res = new_result("Error Handling & Info Leak",
                     "Apakah respons error membocorkan stack trace / detail internal?")
    login = login_path or LOGIN_PATHS[0]
    triggers = [
        ("GET", "/api/nonexistent-" + uuid.uuid4().hex[:6], None, None),
        ("POST", login, "{invalid json", {"Content-Type": "application/json"}),
        ("POST", login, json.dumps({"username": {"$ne": None}, "password": [1, 2]}),
         {"Content-Type": "application/json"}),
        ("GET", "/api/users/%2e%2e%2f%2e%2e%2fetc%2fpasswd", None, None),
        ("GET", "/api/users/'", None, None),
    ]
    leaks, tested = [], 0
    for method, path, body, headers in triggers:
        # Request manual agar path ter-encode tidak dinormalisasi
        req = requests.Request(method, full_url(base_url, path), data=body, headers=headers or {})
        prepped = session.prepare_request(req)
        try:
            r = session.send(prepped, timeout=timeout, verify=False)
        except requests.exceptions.RequestException:
            continue
        tested += 1
        if r.status_code < 400:
            continue
        for pat in LEAK_PATTERNS:
            m = pat.search(r.text)
            if m:
                leaks.append(f"{method} {path} -> HTTP {r.status_code}: '{m.group(0)[:80]}'")
                break

    if leaks:
        res["severity"] = "High"
        res["findings"].append(f"Detail internal bocor pada {len(leaks)} respons error")
        res["evidence"].extend(leaks)
    elif tested:
        res["findings"].append(f"{tested} respons error diuji, tidak ada kebocoran terdeteksi")
    else:
        res["severity"] = "Info"
        res["findings"].append("Tidak ada request error yang berhasil diuji")
    return res


# ==========================================
# TES STATIS (source code)
# ==========================================
def _no_project(name, desc):
    r = new_result(name, desc)
    r["severity"] = "Info"
    r["findings"].append("--project tidak diberikan / path tidak valid")
    return r


def test_05_logging_framework(project):
    res = new_result("Logging Framework", "Analisis dependency & penggunaan logger di source code")
    if not project or not os.path.isdir(project):
        return _no_project(res["test"], res["description"])

    found = set()
    for pj in iter_files(project, names={"package.json"}):
        try:
            data = json.loads(read_text(pj))
        except json.JSONDecodeError:
            continue
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        found.update(fw for fw in LOGGING_FRAMEWORKS if fw in deps)

    console_hits, logger_hits = 0, 0
    for f in iter_files(project, extensions=(".js", ".ts", ".mjs", ".cjs")):
        txt = read_text(f)
        console_hits += len(re.findall(r"\bconsole\.(log|error|warn)\(", txt))
        logger_hits += len(re.findall(r"\blogger\.(info|warn|error|debug)\(", txt))

    res["evidence"].append(f"Pemanggilan console.*: {console_hits} | logger.*: {logger_hits}")
    if not found:
        res["severity"] = "Medium"
        res["findings"].append("Tidak ada framework logging di dependencies (hanya console.log?)")
    else:
        res["findings"].append("Framework logging: " + ", ".join(sorted(found)))
        if logger_hits == 0:
            res["severity"] = "Medium"
            res["findings"].append("Framework terpasang tetapi tidak ada pemanggilan logger.* di kode")
        elif console_hits > logger_hits * 2:
            res["severity"] = "Low"
            res["findings"].append("console.* jauh lebih dominan daripada logger terstruktur")
    return res


def test_06_audit_table(project):
    res = new_result("Audit Trail (skema & kode)", "Apakah ada tabel audit dan kode yang menulis ke sana?")
    if not project or not os.path.isdir(project):
        return _no_project(res["test"], res["description"])

    schema_hits, code_hits = set(), set()
    schema_ext = (".sql", ".prisma")
    for f in iter_files(project, extensions=(".sql", ".prisma", ".js", ".ts")):
        low = read_text(f).lower()
        for kw in AUDIT_KEYWORDS:
            if kw in low:
                base = os.path.basename(f)
                if f.lower().endswith(schema_ext) or "migration" in f.lower() or "schema" in f.lower():
                    schema_hits.add(f"{kw} ({base})")
                else:
                    code_hits.add(f"{kw} ({base})")

    if schema_hits and code_hits:
        res["findings"].append("Tabel audit ada di skema dan direferensikan di kode")
        res["evidence"].extend(sorted(schema_hits)[:5] + sorted(code_hits)[:5])
    elif schema_hits:
        res["severity"] = "Medium"
        res["findings"].append("Tabel audit ada di skema, tetapi tidak ada kode yang terdeteksi menulis ke sana")
        res["evidence"].extend(sorted(schema_hits)[:5])
    else:
        res["severity"] = "High"
        res["findings"].append("Tidak ada tabel audit pada skema/migration")
        res["evidence"].append("Risiko: tidak ada forensik untuk insiden lintas tenant")
    return res


def test_07_nginx_config(project):
    res = new_result("Nginx Logging Config", "access_log/error_log aktif dan file log tidak diekspos")
    if not project or not os.path.isdir(project):
        return _no_project(res["test"], res["description"])

    confs = [f for f in iter_files(project, extensions=(".conf",)) if "nginx" in f.lower() or "conf.d" in f.lower()]
    if not confs:
        res["severity"] = "Info"
        res["findings"].append("Tidak ada file konfigurasi Nginx ditemukan di proyek")
        return res

    text = "\n".join(read_text(f) for f in confs)
    issues = []
    if re.search(r"^\s*access_log\s+off\s*;", text, re.M):
        issues.append("access_log off terdeteksi (cek apakah hanya untuk aset statis)")
    if not re.search(r"^\s*access_log\s+(?!off)\S+", text, re.M):
        issues.append("Tidak ada direktif access_log aktif eksplisit (mengandalkan default)")
    if not re.search(r"^\s*error_log\s+\S+", text, re.M):
        issues.append("Tidak ada direktif error_log eksplisit")
    if not re.search(r"location\s+~\*?\s+.*\\?\.log", text):
        issues.append("Tidak ada rule yang memblokir akses *.log")

    res["evidence"].append(f"File diperiksa: {', '.join(os.path.basename(c) for c in confs[:5])}")
    if issues:
        res["severity"] = "Medium" if len(issues) > 1 else "Low"
        res["findings"].extend(issues)
    else:
        res["findings"].append("Konfigurasi logging Nginx tampak memadai")
    return res


# ==========================================
# MAIN
# ==========================================
def main():
    ap = argparse.ArgumentParser(description="OWASP A09 Security Logging & Monitoring Tester")
    ap.add_argument("--target", required=True, help="Base URL (contoh: https://staging.example.com)")
    ap.add_argument("--authorized", action="store_true",
                    help="Konfirmasi bahwa Anda berwenang menguji target ini")
    ap.add_argument("--project", help="Path source code untuk analisis statis")
    ap.add_argument("--timeout", type=int, default=5, help="Timeout HTTP (detik)")
    ap.add_argument("--attempts", type=int, default=10, help="Jumlah login gagal untuk uji brute-force")
    ap.add_argument("--login-path", help="Path endpoint login (default: auto-detect)")
    ap.add_argument("--container", help="Nama container Docker backend (verifikasi via docker logs)")
    ap.add_argument("--db-url", help="URL PostgreSQL (verifikasi tabel audit via psql)")
    ap.add_argument("--audit-table", default="audit_logs", help="Nama tabel audit")
    ap.add_argument("--audit-time-col", default="created_at", help="Kolom waktu tabel audit")
    ap.add_argument("--json-out", help="Simpan hasil ke file JSON")
    args = ap.parse_args()

    if not args.authorized:
        cprint("Ditolak: tambahkan --authorized untuk mengonfirmasi Anda berwenang menguji target ini.", Colors.FAIL)
        sys.exit(3)

    base = args.target.rstrip("/")
    s = requests.Session()
    s.headers.update({"User-Agent": "SIMITRADUDIKA-A09-Tester/2.0", "Accept": "application/json"})

    cprint("\n" + "=" * 80, Colors.HEADER)
    cprint("  OWASP A09:2021 - Security Logging & Monitoring Tester v2", Colors.BOLD)
    cprint(f"  Target   : {base}", Colors.OKCYAN)
    cprint(f"  Project  : {args.project or 'N/A (dynamic only)'}", Colors.OKCYAN)
    cprint(f"  Container: {args.container or 'N/A'}   DB: {'ya' if args.db_url else 'N/A'}", Colors.OKCYAN)
    cprint("=" * 80 + "\n", Colors.HEADER)

    t = args.timeout
    tests = [
        test_01_bruteforce_detection(base, s, t, args.login_path, args.attempts),
        test_02_log_correlation(base, s, t, args.login_path, args.container,
                                args.db_url, args.audit_table, args.audit_time_col),
        test_03_log_exposure(base, s, t),
        test_04_error_handling(base, s, t, args.login_path),
        test_05_logging_framework(args.project),
        test_06_audit_table(args.project),
        test_07_nginx_config(args.project),
    ]

    cprint(f"{'Test Case':<36}{'Severity':<12}{'Status':<10}", Colors.BOLD)
    cprint("-" * 80)
    summary = {k: 0 for k in SEVERITY_ORDER}
    for r in tests:
        sev = r["severity"]
        summary[sev] += 1
        status = "PASS" if sev == "Pass" else "FAIL" if sev in ("Critical", "High") else \
                 "INFO" if sev == "Info" else "WARN"
        c = severity_color(sev)
        cprint(f"{r['test']:<36}", end="")
        cprint(f"{sev:<12}", c, end="")
        cprint(f"{status:<10}", c)
    cprint("-" * 80)
    cprint("Ringkasan: " + " | ".join(f"{k}={summary[k]}" for k in SEVERITY_ORDER) + "\n", Colors.BOLD)

    cprint("Detail Temuan:", Colors.BOLD)
    cprint("=" * 80)
    for r in tests:
        if r["severity"] == "Pass":
            continue
        cprint(f"\n[{r['severity'].upper()}] {r['test']}", severity_color(r["severity"]))
        cprint(f"  Deskripsi: {r['description']}")
        for f in r["findings"]:
            cprint(f"  -> {f}", Colors.WARNING)
        for ev in r["evidence"]:
            cprint(f"     {ev}", Colors.OKBLUE)

    cprint("\nRekomendasi:", Colors.BOLD)
    cprint("=" * 80)
    recs = []
    names = {r["test"]: r["severity"] for r in tests}
    if names["Brute-force Detection"] == "High":
        recs.append("Pasang rate limiting di login (express-rate-limit dan/atau Nginx limit_req) + lockout akun")
    if names["Log Correlation (server-side)"] in ("High", "Medium"):
        recs.append("Catat event auth (sukses/gagal) dengan winston/pino + request-id, tulis ke stdout & tabel audit")
    if names["Log Path Exposure"] == "Critical":
        recs.append("SEGERA blok akses file log di Nginx dan pindahkan log keluar dari webroot")
    if names["Error Handling & Info Leak"] == "High":
        recs.append("Gunakan error handler global; di production jangan kirim stack trace ke klien")
    if names["Audit Trail (skema & kode)"] in ("High", "Medium"):
        recs.append("Buat tabel audit_logs (tenant_id, user_id, action, ip, created_at) dan tulis dari service layer")
    if names["Logging Framework"] in ("Medium", "Low"):
        recs.append("Ganti console.log dengan logger terstruktur (JSON) agar mudah dianalisis")
    if names["Nginx Logging Config"] in ("Medium", "Low"):
        recs.append("Aktifkan access_log & error_log eksplisit dan tolak akses ke *.log")
    if any(r["severity"] == "Info" for r in tests):
        recs.append("Beberapa tes berstatus Info (tidak terverifikasi); lengkapi opsi --project/--container/--db-url")
    recs.append("Pastikan ada alerting/monitoring (mis. notifikasi lonjakan login gagal); script ini tidak dapat mengujinya")
    for i, rec in enumerate(recs, 1):
        cprint(f"{i}. {rec}", Colors.OKGREEN)
    cprint("\n" + "=" * 80 + "\n", Colors.HEADER)

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump({"target": base, "summary": summary, "results": tests}, f, indent=2, ensure_ascii=False)
        cprint(f"Hasil disimpan ke {args.json_out}", Colors.OKCYAN)

    if summary["Critical"]:
        sys.exit(2)
    if summary["High"]:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
