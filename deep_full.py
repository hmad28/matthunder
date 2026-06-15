"""
deep_full - post-nuclei inline scanner chain.

Runs every registered inline scanner (blh, thirdparty, cred, ssti, cors,
xss, apirecon, params) per active subdomain and aggregates findings to
matthunder_scans.db. Triggered by `python matthunder_cli.py deep X --full`
or `python matthunder_cli.py dark X --full`.

Error policy:
  * Scanner binary missing (FileNotFoundError) -> skip + log, continue.
  * Scanner raised an exception -> abort full chain, raise to caller
    (per "abort on first error" requirement).
"""

import time
from typing import Optional

from scanners import SCANNER_REGISTRY


SCANNER_CHAIN = [
    ("blh",        "Broken Link Hunter"),
    ("thirdparty", "3rd Party Asset Links"),
    ("cred",       "Credential/Config URLs"),
    ("ssti",       "SSTI Probe"),
    ("cors",       "CORS Misconfiguration"),
    ("xss",        "XSS Scan (dalfox)"),
    ("apirecon",   "API Endpoint Recon"),
    ("params",     "Hidden Parameter Discovery"),
]


def _read_subdomains(subdomain_file: str, max_subs: int = 20) -> list[str]:
    if not subdomain_file:
        return []
    import os
    if not os.path.exists(subdomain_file):
        return []
    with open(subdomain_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip()]
    return lines[:max_subs]


def run_full_chain(
    target: str,
    subdomain_file: Optional[str] = None,
    max_subs: int = 20,
    on_error: str = "abort",
) -> dict:
    """Run every registered inline scanner against each active subdomain.

    on_error: 'abort' (default) raises on first unexpected exception.
              'skip' logs and continues.
    """
    subdomains = _read_subdomains(subdomain_file or "", max_subs=max_subs)
    if not subdomains:
        print(f"[!] No subdomains to scan in {subdomain_file}. Run deep scan first.")
        return {"target": target, "subdomains": 0, "scanners": {}, "findings": 0}

    print(f"\n{'=' * 70}")
    print(f"  Full inline scanner chain: {target}")
    print(f"  Subdomains to scan: {len(subdomains)}")
    print(f"  Scanners in chain: {', '.join(s for s, _ in SCANNER_CHAIN)}")
    print(f"{'=' * 70}\n")

    total_findings = 0
    summary: dict = {}
    started = time.time()
    available = set(SCANNER_REGISTRY.keys())

    for idx, sub in enumerate(subdomains, 1):
        print(f"\n--- Subdomain {idx}/{len(subdomains)}: {sub} ---")
        for scanner_code, scanner_label in SCANNER_CHAIN:
            if scanner_code not in available:
                print(f"  [-] {scanner_label:<30} not registered, skip")
                continue
            runner = SCANNER_REGISTRY[scanner_code]
            t0 = time.time()
            try:
                result = runner(sub, [])
            except FileNotFoundError as e:
                print(f"  [-] {scanner_label:<30} missing binary: {e}")
                summary.setdefault(scanner_code, {"runs": 0, "ok": 0, "missing": 0, "errors": 0})
                summary[scanner_code]["missing"] += 1
                continue
            except (ImportError, ModuleNotFoundError) as e:
                print(f"  [-] {scanner_label:<30} module not available: {e}")
                summary.setdefault(scanner_code, {"runs": 0, "ok": 0, "missing": 0, "errors": 0})
                summary[scanner_code]["missing"] += 1
                continue
            except Exception as e:
                print(f"  [!] {scanner_label:<30} crashed: {type(e).__name__}: {e}")
                summary.setdefault(scanner_code, {"runs": 0, "ok": 0, "missing": 0, "errors": 0})
                summary[scanner_code]["errors"] += 1
                if on_error == "abort":
                    print(f"\n[!] Aborting full chain on first error (per --full-abort policy).")
                    raise
                continue
            elapsed = time.time() - t0
            if isinstance(result, dict) and result.get("ok") is False:
                err = result.get("error", "unknown")
                print(f"  [-] {scanner_label:<30} skipped: {err[:80]}")
                summary.setdefault(scanner_code, {"runs": 0, "ok": 0, "missing": 0, "errors": 0})
                summary[scanner_code]["missing"] += 1
                continue
            findings = result.get("links_checked", result.get("links_found",
                          result.get("endpoints", result.get("params",
                          result.get("findings", result.get("probes", 0))))))
            sid = result.get("scan_id", "?")
            sid_short = sid[:12] if isinstance(sid, str) else "?"
            print(f"  [+] {scanner_label:<30} {findings} hits  ({elapsed:.1f}s)  scan_id={sid_short}")
            summary.setdefault(scanner_code, {"runs": 0, "ok": 0, "missing": 0, "errors": 0})
            summary[scanner_code]["runs"] += 1
            summary[scanner_code]["ok"] += 1
            total_findings += findings if isinstance(findings, int) else 0

    elapsed = time.time() - started
    minutes, seconds = divmod(int(elapsed), 60)
    print(f"\n{'=' * 70}")
    print(f"  Full chain complete: {len(subdomains)} subdomains x {len(SCANNER_CHAIN)} scanners")
    print(f"  Total wall time: {minutes}m {seconds}s")
    print(f"  Total findings: {total_findings}")
    print(f"  Per-scanner summary:")
    for code, stats in summary.items():
        label = next((l for c, l in SCANNER_CHAIN if c == code), code)
        print(f"    {label:<30} runs={stats['runs']:<3} ok={stats['ok']:<3} missing={stats['missing']:<3} errors={stats['errors']}")
    print(f"  Results stored in: matthunder_scans.db (table 'results')")

    try:
        from report_gen import generate as gen_report
        res = gen_report(target)
        print(f"\n[REPORT] HTML: {res['html']}")
        print(f"[REPORT] TXT : {res['txt']}")
        print(f"[REPORT] {res['findings']} findings collected (Nuclei + inline scanners)")
    except Exception as e:
        print(f"[!] Report generation failed: {e}")

    print(f"{'=' * 70}\n")
    return {"target": target, "subdomains": len(subdomains), "scanners": summary, "findings": total_findings}
