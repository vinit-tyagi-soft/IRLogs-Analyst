from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .ai_summary import maybe_generate_ai_summary
from .correlate import build_timeline, correlate_events
from .ingest import discover_files, ingest_file
from .normalize import normalize_record
from .report import build_report_payload, write_reports
from .rules import detect_findings, extract_iocs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="irlogs-analyst",
        description="Investigate and correlate multi-source incident response logs.",
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="Input files/directories to ingest recursively.",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory for report outputs.",
    )
    parser.add_argument(
        "--use-ai-summary",
        action="store_true",
        help="Enable optional LLM narrative summary if OPENAI_API_KEY is set.",
    )
    parser.add_argument(
        "--write-normalized",
        action="store_true",
        help="Also export normalized events as JSON for auditability.",
    )
    return parser


def run(args: argparse.Namespace) -> int:
    files = discover_files(args.inputs)
    if not files:
        print("No input files found.", file=sys.stderr)
        return 1

    events = []
    ingest_stats = {"files_seen": len(files), "records_ingested": 0, "by_extension": {}}
    for file_path in files:
        suffix = file_path.suffix.lower() or "<none>"
        ingest_stats["by_extension"][suffix] = ingest_stats["by_extension"].get(suffix, 0) + 1
        for idx, (record, line_num) in enumerate(ingest_file(file_path), start=1):
            event_id = f"{file_path.name}-{line_num}-{idx}"
            event = normalize_record(record, event_id, file_path, line_num)
            events.append(event)
            ingest_stats["records_ingested"] += 1

    timeline = build_timeline(events)
    correlations = correlate_events(timeline)
    findings, skipped_checks = detect_findings(timeline)
    iocs = extract_iocs(timeline)

    ai_payload = {
        "findings": [f.title for f in findings],
        "iocs": iocs,
        "records_ingested": ingest_stats["records_ingested"],
    }
    ai_summary = maybe_generate_ai_summary(args.use_ai_summary, ai_payload)

    payload = build_report_payload(
        events=timeline,
        findings=findings,
        skipped_checks=skipped_checks,
        correlations=correlations,
        iocs=iocs,
        ai_summary=ai_summary,
    )
    payload["scope_input_stats"]["ingest_details"] = ingest_stats

    output_dir = Path(args.output_dir).resolve()
    md_path, json_path = write_reports(output_dir, payload)
    if args.write_normalized:
        normalized = output_dir / "normalized_events.json"
        normalized.write_text(
            json.dumps(payload["timeline"], indent=2),
            encoding="utf-8",
        )

    print(f"Analysis complete. Events={len(timeline)} Findings={len(findings)}")
    print(f"Markdown report: {md_path}")
    print(f"JSON report: {json_path}")
    if args.use_ai_summary and ai_summary is None:
        print("AI summary fallback used (missing key/dependency or request failed).")
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    raise SystemExit(run(args))


if __name__ == "__main__":
    main()
