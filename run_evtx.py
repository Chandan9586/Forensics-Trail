"""CLI runner for ForensicTrail EVTX parser.

Executes parser against target EVTX files without modifying evidence,
exports results to JSON and CSV, and prints a comprehensive parsing report.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import sys

from src.models import NormalizedEvent, ParseSummary
from src.parser import export_csv, export_json, parse_evtx

DEFAULT_EVTX_PATH = r"C:\Users\chand\OneDrive\Documents\sample logs.evtx"
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "reports"


def generate_summary_report(
    evtx_path: Path,
    events: list[NormalizedEvent],
    summary: ParseSummary,
    json_path: Path,
    csv_path: Path,
    report_path: Path,
) -> str:
    """Generate and write a formatted summary report."""
    event_ids = Counter(e.event_id for e in events)
    channels = Counter(e.channel for e in events if e.channel)
    computers = Counter(e.computer for e in events if e.computer)
    providers = Counter(e.provider for e in events if e.provider)

    timestamps = [e.timestamp_utc for e in events if e.timestamp_utc]
    min_time = min(timestamps).isoformat() if timestamps else "N/A"
    max_time = max(timestamps).isoformat() if timestamps else "N/A"

    lines: list[str] = [
        "=" * 70,
        "              FORENSICSTRAIL - EVTX PARSE SUMMARY REPORT",
        "=" * 70,
        f"Generated At          : {datetime.now().isoformat()}",
        f"Input EVTX File       : {evtx_path}",
        f"File Size             : {evtx_path.stat().st_size:,} bytes",
        "-" * 70,
        "EXECUTION METRICS:",
        f"  Total Records Seen  : {summary.records_seen}",
        f"  Records Parsed OK   : {summary.records_parsed}",
        f"  Records Failed      : {summary.records_failed}",
        f"  File Level Error    : {summary.file_error or 'None'}",
        "-" * 70,
    ]

    if summary.errors:
        lines.append(f"ERRORS ENCOUNTERED ({len(summary.errors)}):")
        for idx, err in enumerate(summary.errors, 1):
            lines.append(f"  [{idx}] {err}")
        lines.append("-" * 70)
    else:
        lines.append("ERRORS ENCOUNTERED    : None (0 errors)")
        lines.append("-" * 70)

    lines.extend([
        "TELEMETRY OVERVIEW:",
        f"  Earliest Event Time : {min_time}",
        f"  Latest Event Time   : {max_time}",
        "",
        "Top Event IDs:",
    ])
    for eid, count in event_ids.most_common(10):
        lines.append(f"  EventID {eid:<6} : {count:>5} event(s)")

    if channels:
        lines.append("\nChannels:")
        for ch, count in channels.most_common(5):
            lines.append(f"  {ch:<25} : {count:>5} event(s)")

    if computers:
        lines.append("\nComputers:")
        for comp, count in computers.most_common(5):
            lines.append(f"  {comp:<25} : {count:>5} event(s)")

    if providers:
        lines.append("\nProviders:")
        for prov, count in providers.most_common(5):
            lines.append(f"  {prov:<35} : {count:>5} event(s)")

    lines.extend([
        "-" * 70,
        "OUTPUT ARTIFACTS:",
        f"  JSON Export : {json_path.resolve()}",
        f"  CSV Export  : {csv_path.resolve()}",
        f"  Text Report : {report_path.resolve()}",
        "=" * 70,
    ])

    report_text = "\n".join(lines)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_text, encoding="utf-8")
    return report_text


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse Windows EVTX files using ForensicTrail parser."
    )
    parser.add_argument(
        "evtx_file",
        nargs="?",
        default=DEFAULT_EVTX_PATH,
        help=f"Path to input EVTX file (default: {DEFAULT_EVTX_PATH})",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to save output files (default: {DEFAULT_OUTPUT_DIR})",
    )

    args = parser.parse_args()
    evtx_path = Path(args.evtx_file).resolve()
    out_dir = Path(args.output_dir).resolve()

    print(f"[*] ForensicTrail EVTX Runner")
    print(f"[*] Target file: {evtx_path}")

    # Step 1: Verify existence & readability
    if not evtx_path.exists():
        print(f"[!] Error: File does not exist at '{evtx_path}'", file=sys.stderr)
        return 1

    if not evtx_path.is_file():
        print(f"[!] Error: Target is not a regular file at '{evtx_path}'", file=sys.stderr)
        return 1

    try:
        with open(evtx_path, "rb") as test_f:
            header = test_f.read(8)
            print(f"[*] Verified file is readable. Header magic: {header!r}")
    except Exception as exc:
        print(f"[!] Error reading file '{evtx_path}': {exc}", file=sys.stderr)
        return 1

    # Step 2: Run parser (pure read-only)
    print("[*] Parsing EVTX records...")
    events, summary = parse_evtx(evtx_path)

    # Step 3: Export results
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = evtx_path.stem.replace(" ", "_")
    json_path = out_dir / f"{stem}_events.json"
    csv_path = out_dir / f"{stem}_events.csv"
    report_path = out_dir / f"{stem}_summary_report.txt"

    print(f"[*] Exporting {len(events)} events to JSON: {json_path}")
    export_json(events, json_path)

    print(f"[*] Exporting {len(events)} events to CSV: {csv_path}")
    export_csv(events, csv_path)

    # Step 4: Write summary report and display
    report_text = generate_summary_report(
        evtx_path=evtx_path,
        events=events,
        summary=summary,
        json_path=json_path,
        csv_path=csv_path,
        report_path=report_path,
    )

    print("\n" + report_text)

    if summary.file_error:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

