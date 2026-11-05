# tools/uji_top10.py - OWASP Top 10:2025 untuk SI-MITRA-DUDIKA (CVSS v3.1)
from kalkulator import calculate_cvss

SCENARIOS = [
    ("A01 IDOR/BOLA (lintas tenant)",   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    ("A01 Privilege Escalation",        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"),
    ("A02 Security Misconfig (headers)","CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    ("A03 Supply Chain (dep RCE)",      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("A04 Crypto (hash lemah + DB leak)","CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N"),
    ("A05 SQL Injection",               "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ("A05 Reflected XSS",               "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    ("A06 Insecure Design (logic flaw)","CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"),
    ("A07 Auth (brute force, no limit)","CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    ("A08 Integrity (unsigned update)", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N"),
    ("A09 Logging (no audit trail)",    "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:N"),
    ("A10 Exception (stack trace)",     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
]

print(f"{'Skenario':<36}{'Skor':>5}  {'Severity':<9} Vector")
print("-" * 110)
for name, vec in SCENARIOS:
    try:
        r = calculate_cvss(vec)
        print(f"{name:<36}{r.base_score:>5}  {r.base_severity:<9} {vec}")
    except Exception as e:
        print(f"{name:<36} ERROR: {e}")
print("\nCatatan: A09 skor 0.0 = tidak dinilai CVSS; laporkan sebagai Informational.")
