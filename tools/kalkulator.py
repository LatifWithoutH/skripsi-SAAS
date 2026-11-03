#!/usr/bin/env python3
"""
cvss_calc.py - Kalkulator CVSS ketat untuk SI-MITRA-DUDIKA

CVSS v3.1 : implementasi penuh sesuai spesifikasi FIRST
            (Base + Temporal + Environmental, Roundup resmi, validasi ketat)
CVSS v4.0 : parser + validator ketat (Base, Threat, Environmental, Supplemental).
            Skor dihitung oleh pustaka `cvss` (Red Hat): pip install cvss
            Tanpa pustaka, program menolak menghitung (tidak ada skor palsu).

Pemakaian:
    python cvss_calc.py "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    python cvss_calc.py VEKTOR1 VEKTOR2 --json
    python cvss_calc.py -f daftar_vektor.txt
    python cvss_calc.py --selftest
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass, field


class CVSSError(ValueError):
    """Vektor tidak valid."""


class CVSSDependencyError(RuntimeError):
    """Dependensi untuk v4.0 tidak tersedia."""


# --------------------------------------------------------------------------- #
# Util
# --------------------------------------------------------------------------- #
def severity(score: float) -> str:
    """Rating kualitatif (identik untuk v3.1 dan v4.0)."""
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def roundup31(x: float) -> float:
    """Roundup resmi CVSS v3.1 (Appendix A), kebal error floating-point."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def _parse(vector: str, prefix: str) -> tuple[dict[str, str], list[str]]:
    """Pecah vektor -> dict, sambil menolak duplikat, kosong, dan format rusak."""
    if not isinstance(vector, str):
        raise CVSSError("Vektor harus berupa string")
    vector = vector.strip()
    if not vector.startswith(prefix):
        raise CVSSError(f"Vektor harus diawali '{prefix}'")
    body = vector[len(prefix):]
    if not body:
        raise CVSSError("Vektor kosong setelah prefix")
    metrics: dict[str, str] = {}
    order: list[str] = []
    for part in body.split("/"):
        if part.count(":") != 1:
            raise CVSSError(f"Segmen rusak: '{part}'")
        k, v = part.split(":")
        if not k or not v:
            raise CVSSError(f"Segmen rusak: '{part}'")
        if k in metrics:
            raise CVSSError(f"Metrik duplikat: {k}")
        metrics[k] = v
        order.append(k)
    return metrics, order


# --------------------------------------------------------------------------- #
# CVSS v3.1
# --------------------------------------------------------------------------- #
V31_VALID = {
    # Base
    "AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR", "S": "UC",
    "C": "HLN", "I": "HLN", "A": "HLN",
    # Temporal
    "E": "XHFPU", "RL": "XUWTO", "RC": "XURC",
    # Environmental
    "CR": "XHML", "IR": "XHML", "AR": "XHML",
    "MAV": "XNALP", "MAC": "XLH", "MPR": "XNLH", "MUI": "XNR", "MS": "XUC",
    "MC": "XHLN", "MI": "XHLN", "MA": "XHLN",
}
V31_BASE_REQUIRED = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
V31_ORDER = list(V31_VALID)  # urutan kanonik

W_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
W_AC = {"L": 0.77, "H": 0.44}
W_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}
W_UI = {"N": 0.85, "R": 0.62}
W_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
W_E = {"X": 1.0, "H": 1.0, "F": 0.97, "P": 0.94, "U": 0.91}
W_RL = {"X": 1.0, "U": 1.0, "W": 0.97, "T": 0.96, "O": 0.95}
W_RC = {"X": 1.0, "C": 1.0, "R": 0.96, "U": 0.92}
W_REQ = {"X": 1.0, "H": 1.5, "M": 1.0, "L": 0.5}


@dataclass
class V31Result:
    vector: str
    base_score: float
    base_severity: str
    exploitability: float
    impact: float
    iss: float
    temporal_score: float
    temporal_severity: str
    environmental_score: float
    environmental_severity: str
    modified_impact: float
    modified_exploitability: float
    version: str = "3.1"
    metrics: dict = field(default_factory=dict)

    @property
    def final_score(self) -> float:
        """Skor yang relevan: Environmental bila ada metrik env, kalau tidak Temporal/Base."""
        return self.environmental_score

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class CVSSv31:
    PREFIX = "CVSS:3.1/"

    def __init__(self, vector: str):
        self.metrics, _ = _parse(vector, self.PREFIX)
        self._validate()
        self.vector = self.canonical()

    def _validate(self) -> None:
        for k, v in self.metrics.items():
            if k not in V31_VALID:
                raise CVSSError(f"Metrik tidak dikenal: {k}")
            if v not in V31_VALID[k]:
                raise CVSSError(f"Nilai '{v}' tidak valid untuk {k} (boleh: {V31_VALID[k]})")
        missing = [k for k in V31_BASE_REQUIRED if k not in self.metrics]
        if missing:
            raise CVSSError(f"Metrik Base wajib hilang: {', '.join(missing)}")

    def canonical(self) -> str:
        parts = [f"{k}:{self.metrics[k]}" for k in V31_ORDER if k in self.metrics]
        return self.PREFIX + "/".join(parts)

    def _g(self, key: str, default: str = "X") -> str:
        return self.metrics.get(key, default)

    def calculate(self) -> V31Result:
        m = self.metrics
        scope = m["S"]

        # ---- Base ----
        iss = 1 - ((1 - W_CIA[m["C"]]) * (1 - W_CIA[m["I"]]) * (1 - W_CIA[m["A"]]))
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        expl = 8.22 * W_AV[m["AV"]] * W_AC[m["AC"]] * W_PR[scope][m["PR"]] * W_UI[m["UI"]]

        if impact <= 0:
            base = 0.0
        elif scope == "U":
            base = roundup31(min(impact + expl, 10))
        else:
            base = roundup31(min(1.08 * (impact + expl), 10))

        # ---- Temporal ----
        e, rl, rc = W_E[self._g("E")], W_RL[self._g("RL")], W_RC[self._g("RC")]
        temporal = roundup31(base * e * rl * rc)

        # ---- Environmental ----
        def mod(mkey: str, bkey: str) -> str:
            v = self._g(mkey)
            return m[bkey] if v == "X" else v

        mav, mac = mod("MAV", "AV"), mod("MAC", "AC")
        mui, ms = mod("MUI", "UI"), mod("MS", "S")
        mpr = mod("MPR", "PR")
        mc, mi, ma = mod("MC", "C"), mod("MI", "I"), mod("MA", "A")

        cr, ir, ar = W_REQ[self._g("CR")], W_REQ[self._g("IR")], W_REQ[self._g("AR")]

        miss = min(
            1 - ((1 - cr * W_CIA[mc]) * (1 - ir * W_CIA[mi]) * (1 - ar * W_CIA[ma])),
            0.915,
        )
        if ms == "U":
            mod_impact = 6.42 * miss
        else:
            mod_impact = 7.52 * (miss - 0.029) - 3.25 * (miss * 0.9731 - 0.02) ** 13
        mod_expl = 8.22 * W_AV[mav] * W_AC[mac] * W_PR[ms][mpr] * W_UI[mui]

        if mod_impact <= 0:
            env = 0.0
        elif ms == "U":
            env = roundup31(roundup31(min(mod_impact + mod_expl, 10)) * e * rl * rc)
        else:
            env = roundup31(roundup31(min(1.08 * (mod_impact + mod_expl), 10)) * e * rl * rc)

        return V31Result(
            vector=self.vector,
            base_score=base,
            base_severity=severity(base),
            exploitability=round(expl, 1),
            impact=round(impact, 1),
            iss=round(iss, 4),
            temporal_score=temporal,
            temporal_severity=severity(temporal),
            environmental_score=env,
            environmental_severity=severity(env),
            modified_impact=round(mod_impact, 1),
            modified_exploitability=round(mod_expl, 1),
            metrics=dict(m),
        )


# --------------------------------------------------------------------------- #
# CVSS v4.0  (validator ketat + delegasi skor ke pustaka resmi-compatible)
# --------------------------------------------------------------------------- #
V40_VALID = {
    # Base
    "AV": "NALP", "AC": "LH", "AT": "NP", "PR": "NLH", "UI": "NPA",
    "VC": "HLN", "VI": "HLN", "VA": "HLN", "SC": "HLN", "SI": "HLN", "SA": "HLN",
    # Threat
    "E": "XAPU",
    # Environmental
    "CR": "XHML", "IR": "XHML", "AR": "XHML",
    "MAV": "XNALP", "MAC": "XLH", "MAT": "XNP", "MPR": "XNLH", "MUI": "XNPA",
    "MVC": "XHLN", "MVI": "XHLN", "MVA": "XHLN",
    "MSC": "XHLN", "MSI": "XHLNS", "MSA": "XHLNS",
    # Supplemental
    "S": "XNP", "AU": "XNY", "R": "XAUI", "V": "XDC",
    "RE": "XLMH", "U": "X" + "", 
}
# U (Provider Urgency) bernilai Clear/Green/Amber/Red
V40_VALID["U"] = "XCGAR"
V40_BASE_REQUIRED = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]
V40_ORDER = list(V40_VALID)


class CVSSv40:
    PREFIX = "CVSS:4.0/"

    def __init__(self, vector: str):
        self.metrics, _ = _parse(vector, self.PREFIX)
        self._validate()
        self.vector = self.canonical()

    def _validate(self) -> None:
        for k, v in self.metrics.items():
            if k not in V40_VALID:
                raise CVSSError(f"Metrik tidak dikenal: {k}")
            if v not in V40_VALID[k]:
                raise CVSSError(f"Nilai '{v}' tidak valid untuk {k} (boleh: {V40_VALID[k]})")
        missing = [k for k in V40_BASE_REQUIRED if k not in self.metrics]
        if missing:
            raise CVSSError(f"Metrik Base wajib hilang: {', '.join(missing)}")

    def canonical(self) -> str:
        parts = [f"{k}:{self.metrics[k]}" for k in V40_ORDER if k in self.metrics]
        return self.PREFIX + "/".join(parts)

    def calculate(self) -> dict:
        try:
            from cvss import CVSS4  # type: ignore
        except ImportError as exc:
            raise CVSSDependencyError(
                "Skor CVSS v4.0 membutuhkan pustaka 'cvss'. Jalankan: pip install cvss\n"
                "(Sengaja tidak ada fallback: formula v4.0 tanpa lookup MacroVector "
                "resmi akan menghasilkan skor yang salah.)"
            ) from exc

        c = CVSS4(self.vector)
        score = float(c.base_score)
        return {
            "version": "4.0",
            "vector": self.vector,
            "base_score": score,
            "base_severity": severity(score),
            "metrics": dict(self.metrics),
            "nomenclature": _v40_nomenclature(self.metrics),
        }


def _v40_nomenclature(m: dict[str, str]) -> str:
    """CVSS-B / CVSS-BT / CVSS-BE / CVSS-BTE sesuai metrik yang diisi."""
    threat = m.get("E", "X") != "X"
    env_keys = ["CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI",
                "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"]
    env = any(m.get(k, "X") != "X" for k in env_keys)
    return "CVSS-" + "B" + ("T" if threat else "") + ("E" if env else "")


# --------------------------------------------------------------------------- #
# API publik
# --------------------------------------------------------------------------- #
def calculate_cvss(vector: str):
    """Auto-detect versi. v3.1 -> V31Result (dataclass), v4.0 -> dict."""
    vector = vector.strip()
    if vector.startswith(CVSSv31.PREFIX):
        return CVSSv31(vector).calculate()
    if vector.startswith(CVSSv40.PREFIX):
        return CVSSv40(vector).calculate()
    if vector.startswith(("CVSS:3.0/", "CVSS:2.0/")) or vector.startswith("AV:"):
        raise CVSSError("Hanya CVSS v3.1 dan v4.0 yang didukung")
    raise CVSSError("Vektor harus diawali 'CVSS:3.1/' atau 'CVSS:4.0/'")


# --------------------------------------------------------------------------- #
# Self-test (vektor referensi publik / kalkulator FIRST)
# --------------------------------------------------------------------------- #
V31_TESTS = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
]


def selftest() -> int:
    fails = 0
    for vec, expected in V31_TESTS:
        got = CVSSv31(vec).calculate().base_score
        ok = got == expected
        fails += not ok
        print(f"[{'OK' if ok else 'FAIL'}] {vec}  expected={expected} got={got}")

    # Temporal: 9.8 * 0.94 * 0.95 = 8.75 -> 8.8
    t = CVSSv31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O/RC:C").calculate()
    ok = t.temporal_score == 8.8
    fails += not ok
    print(f"[{'OK' if ok else 'FAIL'}] temporal E:P/RL:O/RC:C expected=8.8 got={t.temporal_score}")

    # Environmental tanpa modifikasi harus == base (tanpa temporal)
    e = CVSSv31("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N").calculate()
    ok = e.environmental_score == e.base_score
    fails += not ok
    print(f"[{'OK' if ok else 'FAIL'}] env tanpa modifikasi == base ({e.environmental_score})")

    # Validasi harus menolak input busuk
    bad = [
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # nilai invalid
        "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # duplikat
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",       # metrik hilang
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/ZZ:1",  # metrik asing
        "CVSS:3.1/AV:N//AC:L",                            # segmen rusak
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # versi tidak didukung
    ]
    for b in bad:
        try:
            calculate_cvss(b)
            print(f"[FAIL] seharusnya ditolak: {b}")
            fails += 1
        except CVSSError:
            print(f"[OK] ditolak: {b}")

    # v4.0: validator
    good40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
    CVSSv40(good40)
    print("[OK] v4.0 vektor valid diterima")
    try:
        CVSSv40("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N")
        print("[FAIL] v4.0 metrik hilang tidak ditolak")
        fails += 1
    except CVSSError:
        print("[OK] v4.0 metrik hilang ditolak")

    print("\nSEMUA TEST LULUS" if not fails else f"\n{fails} TEST GAGAL")
    return 1 if fails else 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _print_human(r) -> None:
    if isinstance(r, V31Result):
        print(f"CVSS v3.1  {r.vector}")
        print(f"  Base          : {r.base_score:>4}  ({r.base_severity})")
        print(f"    Exploitab.  : {r.exploitability}   Impact: {r.impact}   ISS: {r.iss}")
        print(f"  Temporal      : {r.temporal_score:>4}  ({r.temporal_severity})")
        print(f"  Environmental : {r.environmental_score:>4}  ({r.environmental_severity})")
    else:
        print(f"CVSS v4.0  {r['vector']}")
        print(f"  {r['nomenclature']}: {r['base_score']}  ({r['base_severity']})")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Kalkulator CVSS v3.1 / v4.0")
    ap.add_argument("vectors", nargs="*", help="satu atau lebih vektor CVSS")
    ap.add_argument("-f", "--file", help="file berisi satu vektor per baris")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--selftest", action="store_true", help="jalankan test internal")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    vectors = list(args.vectors)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            vectors += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    if not vectors:
        ap.print_help()
        return 2

    out, rc = [], 0
    for v in vectors:
        try:
            r = calculate_cvss(v)
            out.append(r.to_dict() if isinstance(r, V31Result) else r)
            if not args.json:
                _print_human(r)
                print()
        except (CVSSError, CVSSDependencyError) as exc:
            rc = 1
            out.append({"vector": v, "error": str(exc)})
            if not args.json:
                print(f"ERROR  {v}\n  -> {exc}\n", file=sys.stderr)

    if args.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    return rc


if __name__ == "__main__":
    sys.exit(main())
