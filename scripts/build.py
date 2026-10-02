#!/usr/bin/env python3
"""Regenerate the findings tables and stats in README.md from findings.json.

Usage: python3 scripts/build.py
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
DATA = ROOT / "findings.json"

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_LABEL = {
    "critical": "🟥 `CRITICAL`",
    "high": "🟧 `HIGH`",
    "medium": "🟨 `MEDIUM`",
    "low": "🟦 `LOW`",
    "info": "⬜ `INFO`",
}
STATUS_LABEL = {
    "fixed": "✅ fixed",
    "confirmed": "☑️ confirmed",
    "triaged": "⏳ triaged",
    "duplicate": "♻️ duplicate",
    "disclosed": "📢 disclosed",
    "private": "🔒 private",
}


def cell(value):
    """Escape a value so it cannot break a markdown table row."""
    return str(value or "—").replace("|", "\\|").replace("\n", " ")


def link(item):
    url = item.get("report")
    return f"[`read →`]({url})" if url else "`redacted`"


def with_ids(items, prefix):
    # IDs follow file order (append new findings at the end); display newest first.
    numbered = [(f"{prefix}-{i:03d}", item) for i, item in enumerate(items, 1)]
    return sorted(numbered, key=lambda p: p[1].get("date", ""), reverse=True)


def check(items, kind):
    for i, item in enumerate(items, 1):
        sev = item.get("severity")
        if sev not in SEVERITIES:
            sys.exit(f"{kind}[{i}]: severity must be one of {SEVERITIES}, got {sev!r}")
        if not item.get("title"):
            sys.exit(f"{kind}[{i}]: missing title")


def table(header, rows, empty):
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    if not rows:
        rows = [[f"_{empty}_"] + [""] * (len(header) - 1)]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(lines)


def web3_table(items):
    rows = [
        [
            f"`{fid}`",
            SEV_LABEL[it["severity"]],
            cell(it.get("protocol")),
            cell(it["title"]),
            cell(it.get("class")),
            cell(it.get("platform")),
            STATUS_LABEL.get(it.get("status"), cell(it.get("status"))),
            link(it),
        ]
        for fid, it in with_ids(items, "W3")
    ]
    header = ["ID", "Severity", "Protocol", "Finding", "Class", "Platform", "Status", "Report"]
    return table(header, rows, "no findings disclosed yet")


def web2_ref(item):
    """CVE id (linked to NVD) for CVEs, bounty platform otherwise."""
    cve = item.get("cve")
    if cve:
        return f"[`{cve}`](https://nvd.nist.gov/vuln/detail/{cve})"
    return cell(item.get("platform"))


def web2_severity(item):
    label = SEV_LABEL[item["severity"]]
    return f"{label} {item['cvss']}" if item.get("cvss") else label


def web2_table(items):
    rows = [
        [
            f"`{fid}`",
            web2_severity(it),
            cell(it.get("target")),
            cell(it["title"]),
            cell(it.get("class")),
            web2_ref(it),
            STATUS_LABEL.get(it.get("status"), cell(it.get("status"))),
            link(it),
        ]
        for fid, it in with_ids(items, "W2")
    ]
    header = ["ID", "Severity", "Target", "Finding", "Class", "CVE / Platform", "Status", "Report"]
    return table(header, rows, "no findings disclosed yet")


def stats(web3, web2):
    def count(items, sev):
        return sum(1 for it in items if it["severity"] == sev)

    rows = [(s.upper(), count(web3, s), count(web2, s)) for s in SEVERITIES]
    rows = [r for r in rows if r[1] or r[2] or r[0] != "INFO"]
    out = [
        "```text",
        "$ ./loot --summary",
        "┌──────────┬──────┬──────┬───────┐",
        "│ SEVERITY │ WEB3 │ WEB2 │ TOTAL │",
        "├──────────┼──────┼──────┼───────┤",
    ]
    for name, a, b in rows:
        out.append(f"│ {name:<8} │ {a:>4} │ {b:>4} │ {a + b:>5} │")
    out += [
        "├──────────┼──────┼──────┼───────┤",
        f"│ {'TOTAL':<8} │ {len(web3):>4} │ {len(web2):>4} │ {len(web3) + len(web2):>5} │",
        "└──────────┴──────┴──────┴───────┘",
        "```",
    ]
    return "\n".join(out)


def inject(text, name, body):
    pattern = re.compile(rf"(<!-- {name}:START -->).*?(<!-- {name}:END -->)", re.S)
    if not pattern.search(text):
        sys.exit(f"README.md is missing the {name} markers")
    return pattern.sub(lambda m: f"{m.group(1)}\n{body}\n{m.group(2)}", text)


def main():
    data = json.loads(DATA.read_text(encoding="utf-8"))
    web3, web2 = data.get("web3", []), data.get("web2", [])
    check(web3, "web3")
    check(web2, "web2")

    text = README.read_text(encoding="utf-8")
    text = inject(text, "STATS", stats(web3, web2))
    text = inject(text, "WEB3", web3_table(web3))
    text = inject(text, "WEB2", web2_table(web2))
    README.write_text(text, encoding="utf-8")
    print(f"README.md updated: {len(web3)} web3, {len(web2)} web2")


if __name__ == "__main__":
    main()
