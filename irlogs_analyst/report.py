from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import Event, Finding


def build_report_payload(
    events: list[Event],
    findings: list[Finding],
    skipped_checks: list[str],
    correlations: dict[str, Any],
    iocs: dict[str, list[str]],
    ai_summary: str | None = None,
) -> dict[str, Any]:
    timeline = [event_to_dict(event) for event in events]
    action_counts = Counter([event.event_type or "unknown" for event in events])
    severity_counts = Counter([event.severity or "unknown" for event in events])

    top_findings = sorted(findings, key=lambda f: (f.confidence, f.severity), reverse=True)
    if top_findings:
        deterministic_summary = (
            f"Analyzed {len(events)} events and identified {len(findings)} notable findings. "
            f"Highest-confidence issue: {top_findings[0].title} (confidence {top_findings[0].confidence:.2f})."
        )
    else:
        deterministic_summary = f"Analyzed {len(events)} events and found no high-signal suspicious patterns."

    narrative = ai_summary or deterministic_summary
    hypothesis = _build_hypothesis(findings)
    unanswered = _build_unanswered_questions(events, findings)
    timeline_highlights = _timeline_highlights(events, findings)

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "executive_summary": narrative,
        "scope_input_stats": {
            "event_count": len(events),
            "finding_count": len(findings),
            "event_type_distribution": dict(action_counts),
            "severity_distribution": dict(severity_counts),
            "skipped_checks": skipped_checks,
        },
        "timeline_highlights": timeline_highlights,
        "correlated_evidence_graph_summary": correlations.get("graph_summary", []),
        "key_findings": [finding_to_dict(finding) for finding in top_findings],
        "what_how_why_hypothesis": hypothesis,
        "iocs_extracted": iocs,
        "unanswered_questions": unanswered,
        "timeline": timeline,
    }


def write_reports(output_dir: Path, payload: dict[str, Any]) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "report.json"
    md_path = output_dir / "report.md"
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    return md_path, json_path


def render_markdown(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Incident Investigation Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(payload["executive_summary"])
    lines.append("")
    lines.append("## Scope / Input Stats")
    scope = payload["scope_input_stats"]
    lines.append(f"- Events analyzed: {scope['event_count']}")
    lines.append(f"- Findings: {scope['finding_count']}")
    lines.append(f"- Event types: {scope['event_type_distribution']}")
    lines.append(f"- Severity distribution: {scope['severity_distribution']}")
    for skip in scope.get("skipped_checks", []):
        lines.append(f"- Skipped check: {skip}")
    lines.append("")
    lines.append("## Timeline Highlights")
    for item in payload["timeline_highlights"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Correlated Evidence Graph Summary")
    if payload["correlated_evidence_graph_summary"]:
        for edge in payload["correlated_evidence_graph_summary"][:20]:
            lines.append(
                f"- {edge['left_type']}:{edge['left_value']} <-> {edge['right_type']}:{edge['right_value']} "
                f"(co-occurred {edge['count']} times)"
            )
    else:
        lines.append("- No strong correlation edges identified.")
    lines.append("")
    lines.append("## Key Findings (What / How / Why)")
    if payload["key_findings"]:
        for finding in payload["key_findings"]:
            lines.append(f"### {finding['title']}")
            lines.append(f"- Confidence: {finding['confidence']} ({finding['confidence_label']})")
            lines.append(f"- Category: {finding['category']} | Severity: {finding['severity']}")
            lines.append(f"- Description: {finding['description']}")
            lines.append(f"- Evidence: {', '.join(finding['evidence'])}")
    else:
        lines.append("- No findings triggered based on current deterministic rules.")
    lines.append("")
    lines.append("## IOCs Extracted")
    iocs = payload["iocs_extracted"]
    lines.append(f"- IPs: {', '.join(iocs['ips']) if iocs['ips'] else 'None'}")
    lines.append(f"- File hashes: {', '.join(iocs['file_hashes']) if iocs['file_hashes'] else 'None'}")
    lines.append(f"- Domains: {', '.join(iocs['domains']) if iocs['domains'] else 'None'}")
    lines.append("")
    lines.append("## Unanswered Questions")
    for question in payload["unanswered_questions"]:
        lines.append(f"- {question}")
    return "\n".join(lines) + "\n"


def event_to_dict(event: Event) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "host": event.host,
        "source": event.source,
        "user": event.user,
        "process": event.process,
        "action": event.action,
        "event_type": event.event_type,
        "severity": event.severity,
        "ip": event.ip,
        "file_hash": event.file_hash,
        "parent_process": event.parent_process,
        "command_line": event.command_line,
        "evidence_ref": event.evidence_ref(),
    }


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    return {
        "finding_id": finding.finding_id,
        "title": finding.title,
        "description": finding.description,
        "confidence": round(finding.confidence, 2),
        "confidence_label": finding.confidence_label,
        "category": finding.category,
        "severity": finding.severity,
        "evidence": finding.evidence,
        "related_entities": finding.related_entities,
    }


def _timeline_highlights(events: list[Event], findings: list[Finding]) -> list[str]:
    if not events:
        return ["No events available."]
    highlights = []
    first = next((e for e in events if e.timestamp is not None), events[0])
    last = next((e for e in reversed(events) if e.timestamp is not None), events[-1])
    highlights.append(f"Timeline window: {first.timestamp} -> {last.timestamp}")
    highlights.append(f"Distinct hosts observed: {len({e.host for e in events if e.host})}")
    highlights.append(f"Distinct users observed: {len({e.user for e in events if e.user})}")
    if findings:
        top = sorted(findings, key=lambda f: f.confidence, reverse=True)[:3]
        for finding in top:
            highlights.append(f"Top signal: {finding.title} ({finding.confidence_label} confidence)")
    return highlights


def _build_hypothesis(findings: list[Finding]) -> str:
    if not findings:
        return "No strong attack hypothesis can be formed from current data; collect more endpoint and auth telemetry."
    categories = Counter([f.category for f in findings])
    dominant = categories.most_common(2)
    return (
        "Likely activity includes "
        + ", ".join([f"{count} indicators in {cat}" for cat, count in dominant])
        + ". This suggests adversary execution and follow-on actions supported by correlated host/user/process evidence."
    )


def _build_unanswered_questions(events: list[Event], findings: list[Finding]) -> list[str]:
    questions = []
    if not any(e.ip for e in events):
        questions.append("No source/destination IP fields were present; network traceability is limited.")
    if not any(e.file_hash for e in events):
        questions.append("No file hashes observed; malware lineage and VT pivoting are limited.")
    if not findings:
        questions.append("No high-confidence detections fired. Were relevant security logs fully collected?")
    questions.append("Were endpoint EDR alerts, DNS logs, and proxy logs available for cross-validation?")
    return questions
