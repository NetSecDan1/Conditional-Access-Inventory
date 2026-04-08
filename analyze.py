#!/usr/bin/env python3
"""CA Policy Inventory & Gap Analysis Tool — main entry point.

Usage:
    python analyze.py --input policies.json --tenant "Contoso"
    python analyze.py --input policies.json --config config.json --no-open
"""

import argparse
import json
import os
import sys
import webbrowser
from datetime import datetime

from gap_engine import GapEngine
from models import Stats
from parser import ParseError, PolicyParser
from recommender import Recommender
from visualizer import ReportBuilder

# ── Terminal colours (suppressed when not a TTY) ────────────────────────────
_TTY    = sys.stdout.isatty()
BOLD    = "\033[1m"  if _TTY else ""
DIM     = "\033[2m"  if _TTY else ""
RED     = "\033[91m" if _TTY else ""
YELLOW  = "\033[93m" if _TTY else ""
CYAN    = "\033[96m" if _TTY else ""
GREEN   = "\033[92m" if _TTY else ""
RESET   = "\033[0m"  if _TTY else ""

_SEV_COLOR = {"Critical": RED, "High": YELLOW, "Medium": CYAN, "Low": DIM}

_HERE = os.path.dirname(os.path.abspath(__file__))


# ── Helpers ─────────────────────────────────────────────────────────────────

def _sev_counts(gaps):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for g in gaps:
        counts[g.severity] = counts.get(g.severity, 0) + 1
    return counts


def _compute_stats(policies, gaps) -> Stats:
    enabled  = [p for p in policies if p.is_enabled]
    disabled = [p for p in policies if p.is_disabled]
    ro       = [p for p in policies if p.is_report_only]
    counts   = _sev_counts(gaps)
    c, h, m, l = counts["Critical"], counts["High"], counts["Medium"], counts["Low"]

    if c > 0 or h > 2:
        posture = "Red"
    elif h > 0 or m > 3:
        posture = "Amber"
    else:
        posture = "Green"

    dates = sorted(p.modified_datetime for p in policies if p.modified_datetime)
    export_date = dates[-1][:10] if dates else None

    return Stats(
        total=len(policies), enabled=len(enabled),
        disabled=len(disabled), report_only=len(ro),
        critical_gaps=c, high_gaps=h, medium_gaps=m, low_gaps=l,
        posture=posture, export_date=export_date,
    )


def _load_config(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  [warn] Could not load config '{path}': {exc}")
        return {}


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        prog="analyze.py",
        description="CA Policy Inventory & Gap Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python analyze.py --input policies.json\n"
            "  python analyze.py --input policies.json --tenant Contoso\n"
            "  python analyze.py --input policies.json --config custom.json --no-open"
        ),
    )
    ap.add_argument("--input",      required=True,  metavar="FILE", help="Path to Graph JSON export")
    ap.add_argument("--tenant",     default="",     metavar="NAME", help="Tenant name for report branding")
    ap.add_argument("--config",     default=os.path.join(_HERE, "config.json"),
                                    metavar="FILE", help="Rule config file (default: config.json)")
    ap.add_argument("--output-dir", default=os.path.join(_HERE, "output"),
                                    metavar="DIR",  help="Output directory (default: ./output)")
    ap.add_argument("--no-open",    action="store_true", help="Do not auto-open the report in a browser")
    args = ap.parse_args()

    print(f"\n{BOLD}CA Policy Inventory & Gap Analysis{RESET}")
    print("─" * 40)

    # Config
    config = _load_config(args.config)
    if args.tenant:
        config.setdefault("org", {})["name"] = args.tenant
    tenant_name = config.get("org", {}).get("name") or "Unknown Tenant"

    # Parse
    print(f"Loading {BOLD}{args.input}{RESET}...")
    try:
        policies = PolicyParser().parse(args.input)
    except ParseError as exc:
        print(f"\n{RED}Error:{RESET} {exc}\n", file=sys.stderr)
        sys.exit(1)

    n_enabled  = sum(1 for p in policies if p.is_enabled)
    n_disabled = sum(1 for p in policies if p.is_disabled)
    n_ro       = sum(1 for p in policies if p.is_report_only)
    print(
        f"Parsed {BOLD}{len(policies)}{RESET} policies  "
        f"({GREEN}{n_enabled} enabled{RESET} · "
        f"{DIM}{n_disabled} disabled{RESET} · "
        f"{CYAN}{n_ro} report-only{RESET})"
    )

    # Gap analysis
    print("Running gap analysis...", end=" ", flush=True)
    gaps = GapEngine(config).analyze(policies)
    print(f"{len(gaps)} findings")

    counts = _sev_counts(gaps)
    parts = [
        f"{_SEV_COLOR[s]}{BOLD}{counts[s]} {s}{RESET}"
        for s in ("Critical", "High", "Medium", "Low")
        if counts[s]
    ]
    if parts:
        print("Found: " + " | ".join(parts))
    else:
        print(f"{GREEN}No gaps detected — great posture!{RESET}")

    # Build report
    print("Generating report...", end=" ", flush=True)
    sorted_gaps = Recommender().sorted_gaps(gaps)
    stats       = _compute_stats(policies, gaps)
    html        = ReportBuilder(tenant_name).build(policies, sorted_gaps, stats)

    os.makedirs(args.output_dir, exist_ok=True)
    ts       = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = os.path.join(args.output_dir, f"ca-report-{ts}.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    print("done")
    print(f"Report saved: {BOLD}{out_path}{RESET}")

    if not args.no_open:
        webbrowser.open(f"file://{os.path.abspath(out_path)}")
        print("Opening in browser...")

    print()


if __name__ == "__main__":
    main()
