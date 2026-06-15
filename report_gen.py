"""
report_gen - consolidated HTML report builder.

Aggregates findings from:
  - nuclei/nuc_active_*.txt, nuc_exp_*.txt, nuc_dast_*.txt, take_over/TOW_*.txt
  - matthunder_scans.db (inline scanners: blh, thirdparty, cred, ssti, cors, xss, apirecon, params)

Output:
  - reports/<target>_<timestamp>.html  (styled, sortable sections)
  - reports/<target>_<timestamp>.txt   (plain text fallback)

Auto-called by deep_full.run_full_chain() at the end of every chain.
"""

import html
import os
import re
import sqlite3
import time
from typing import Optional
from urllib.parse import urlparse


REPORT_DIR = "reports"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
SEVERITY_COLORS = {
    "critical": "#7c1d3f",
    "high":     "#c0392b",
    "medium":   "#d68910",
    "low":      "#229954",
    "info":     "#2874a6",
    "unknown":  "#5d6d7e",
}


NUCLEI_LINE_RE = re.compile(
    r"\[(?P<template>[^\]]+)\]\s+\[(?P<protocol>[^\]]+)\]\s+\[(?P<severity>[^\]]+)\]\s+(?P<url>\S+)(?:\s+(?P<extra>.+))?$"
)


def _read_lines(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.rstrip("\n") for line in f if line.strip()]
    except (OSError, IOError):
        return []


def _parse_nuclei(path: str, source: str) -> list[dict]:
    out: list[dict] = []
    for line in _read_lines(path):
        m = NUCLEI_LINE_RE.match(line)
        if not m:
            continue
        out.append({
            "source": source,
            "template": m.group("template"),
            "protocol": m.group("protocol"),
            "severity": m.group("severity").lower(),
            "url": m.group("url"),
            "extra": m.group("extra") or "",
            "raw": line,
        })
    return out


def _parse_sqlite(target: str) -> list[dict]:
    out: list[dict] = []
    db_path = "matthunder_scans.db"
    if not os.path.exists(db_path):
        return out
    try:
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT scanner, category, target_url, source_url, anchor, status, http_code, detail "
            "FROM results r JOIN scans s ON s.id = r.scan_id "
            "WHERE s.domain = ? OR r.target_url LIKE ? OR r.target_url LIKE ? "
            "ORDER BY r.id ASC",
            (target, f"%.{target}", f"%/{target}"),
        ).fetchall()
    except Exception:
        return out
    finally:
        try:
            con.close()
        except Exception:
            pass

    for r in rows:
        scanner = r["scanner"] or "unknown"
        status = (r["status"] or "").lower()
        if "vulnerable" in status or "broken" in status or "alive" in status:
            severity = "high" if "broken" in status else ("medium" if "vulnerable" in status else "info")
        elif "match" in status or "discovered" in status:
            severity = "low"
        elif "timeout" in status or "blocked" in status:
            severity = "info"
        else:
            severity = "info"
        out.append({
            "source": f"scanner:{scanner}",
            "template": f"{scanner}/{r['category'] or 'finding'}",
            "protocol": "scanner",
            "severity": severity,
            "url": r["target_url"] or "",
            "extra": f"status={r['status']} code={r['http_code']} detail={r['detail']} anchor={r['anchor']}",
            "raw": f"{scanner} {r['category']} {r['target_url']} {r['status']} {r['detail']}",
        })
    return out


def collect_findings(target: str) -> list[dict]:
    """Pull findings from Nuclei files + SQLite inline scanner DB."""
    files = [
        ("Nuclei (basic)",       os.path.join("nuclei",         f"nuc_active_{target}.txt")),
        ("Nuclei (JS/exposure)", os.path.join("nuclei",         f"nuc_exp_{target}.txt")),
        ("Nuclei (DAST)",        os.path.join("nuclei",         f"nuc_dast_{target}.txt")),
        ("Takeover (single)",    os.path.join("take_over",      f"TOW_{target}.txt")),
        ("Takeover (mass)",      os.path.join("take_over",      f"TO_{target}.txt")),
    ]
    findings: list[dict] = []
    for source, path in files:
        if not os.path.exists(path):
            continue
        parsed = _parse_nuclei(path, source)
        if parsed:
            findings.extend(parsed)
        else:
            for line in _read_lines(path):
                findings.append({
                    "source": source,
                    "template": "raw",
                    "protocol": "?",
                    "severity": "info",
                    "url": line.strip(),
                    "extra": "",
                    "raw": line,
                })
    findings.extend(_parse_sqlite(target))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 99), f["template"]))
    return findings


def _esc(s: str) -> str:
    return html.escape(s or "")


def _html_doc(target: str, findings: list[dict], meta: dict) -> str:
    css = """
    body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 24px; background: #f4f6f9; color: #1c2833; }
    h1 { margin: 0 0 4px; font-size: 28px; }
    h2 { margin: 24px 0 8px; font-size: 18px; border-bottom: 2px solid #ccd1d9; padding-bottom: 4px; }
    .meta { color: #5d6d7e; font-size: 13px; margin-bottom: 16px; }
    .meta span { display: inline-block; margin-right: 18px; }
    .card { background: #fff; border: 1px solid #e5e8e8; border-radius: 6px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #ecf0f1; vertical-align: top; }
    th { background: #f8f9fa; font-weight: 600; color: #34495e; }
    tr:hover td { background: #fafbfc; }
    .sev { display: inline-block; padding: 2px 8px; border-radius: 3px; color: #fff; font-size: 11px; font-weight: 600; text-transform: uppercase; }
    .url { font-family: 'Consolas', 'Courier New', monospace; word-break: break-all; }
    .empty { padding: 32px; text-align: center; color: #95a5a6; font-style: italic; }
    .raw { font-family: monospace; font-size: 12px; color: #566573; }
    .footer { margin-top: 24px; padding-top: 12px; border-top: 1px solid #ccd1d9; font-size: 11px; color: #95a5a6; text-align: center; }
    .stats { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
    .stat { background: #fff; border: 1px solid #e5e8e8; border-radius: 4px; padding: 8px 14px; min-width: 100px; }
    .stat .num { font-size: 22px; font-weight: 700; }
    .stat .lbl { font-size: 11px; color: #5d6d7e; text-transform: uppercase; }
    """
    total = len(findings)
    by_sev = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    rows = []
    for f in findings:
        sev = f["severity"]
        color = SEVERITY_COLORS.get(sev, "#5d6d7e")
        rows.append(
            f"<tr>"
            f"<td><span class='sev' style='background:{color}'>{_esc(sev)}</span></td>"
            f"<td>{_esc(f['source'])}</td>"
            f"<td>{_esc(f['template'])}</td>"
            f"<td class='url'><a href='{_esc(f['url'])}' target='_blank' rel='noopener noreferrer'>{_esc(f['url'])}</a></td>"
            f"<td class='raw'>{_esc(f['extra'])}</td>"
            f"</tr>"
        )
    rows_html = "\n".join(rows) if rows else "<tr><td colspan='5' class='empty'>No findings for this target.</td></tr>"

    stats_html = "".join(
        f"<div class='stat'><div class='num' style='color:{SEVERITY_COLORS.get(sev, '#5d6d7e')}'>{by_sev.get(sev, 0)}</div>"
        f"<div class='lbl'>{sev}</div></div>"
        for sev in SEVERITY_ORDER
    )

    meta_html = " ".join(f"<span><b>{_esc(k)}:</b> {_esc(str(v))}</span>" for k, v in meta.items())

    return f"""<!doctype html>
<html><head><meta charset='utf-8'>
<title>matthunder report — {_esc(target)}</title>
<style>{css}</style>
</head><body>
<h1>matthunder scan report</h1>
<div class='meta'>{meta_html}</div>

<div class='card'>
<h2 style='margin-top:0'>Severity summary</h2>
<div class='stats'>{stats_html}</div>
<p style='margin:0;color:#5d6d7e;font-size:12px'>Total findings: <b>{total}</b></p>
</div>

<div class='card'>
<h2 style='margin-top:0'>Findings</h2>
<table>
<thead><tr><th>Severity</th><th>Source</th><th>Template</th><th>URL</th><th>Detail</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>
</div>

<div class='footer'>matthunder by @hmad28 / github.com/hmad28/matthunder</div>
</body></html>"""


def _txt_doc(target: str, findings: list[dict], meta: dict) -> str:
    by_sev = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    lines = [
        f"matthunder scan report — {target}",
        "=" * 70,
    ]
    for k, v in meta.items():
        lines.append(f"{k}: {v}")
    lines += [
        "",
        "Severity summary:",
    ]
    for sev in SEVERITY_ORDER:
        lines.append(f"  {sev:<10} {by_sev.get(sev, 0)}")
    lines += [
        "",
        f"Total findings: {len(findings)}",
        "",
        "Findings:",
        "-" * 70,
    ]
    if not findings:
        lines.append("(no findings)")
    for i, f in enumerate(findings, 1):
        lines.append(f"[{i}] {f['severity'].upper():<8} {f['source']:<24} {f['template']}")
        lines.append(f"    URL:   {f['url']}")
        if f["extra"]:
            lines.append(f"    Info:  {f['extra']}")
        lines.append("")
    lines.append("=" * 70)
    lines.append("matthunder by @hmad28 / github.com/hmad28/matthunder")
    return "\n".join(lines)


def generate(target: str, out_dir: str = REPORT_DIR) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    findings = collect_findings(target)
    ts = time.strftime("%Y%m%d_%H%M%S")
    html_path = os.path.join(out_dir, f"{target}_{ts}.html")
    txt_path = os.path.join(out_dir, f"{target}_{ts}.txt")
    meta = {
        "target": target,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "findings": len(findings),
    }
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(_html_doc(target, findings, meta))
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(_txt_doc(target, findings, meta))
    return {"html": html_path, "txt": txt_path, "findings": len(findings)}


def main():
    import argparse
    p = argparse.ArgumentParser(description="matthunder consolidated report generator")
    p.add_argument("target", help="Target domain (e.g. example.com)")
    p.add_argument("-o", "--output", default=REPORT_DIR)
    args = p.parse_args()
    res = generate(args.target, args.output)
    print(f"[OK] HTML: {res['html']}")
    print(f"[OK] TXT:  {res['txt']}")
    print(f"[OK] {res['findings']} findings collected")


if __name__ == "__main__":
    main()
