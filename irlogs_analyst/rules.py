from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from typing import Any

from .models import Event, Finding
from .utils import to_lower_text


SUSPICIOUS_PARENT_CHILD = {
    ("winword.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("outlook.exe", "wscript.exe"),
    ("powershell.exe", "rundll32.exe"),
}

PERSISTENCE_KEYWORDS = [
    "scheduled task",
    "schtasks",
    "run key",
    "startup",
    "cron",
    "systemd",
    "service created",
]


def detect_findings(events: list[Event]) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    skipped_checks: list[str] = []

    findings.extend(_auth_failure_burst(events))
    findings.extend(_encoded_powershell(events))
    findings.extend(_temp_process_exec(events))
    findings.extend(_suspicious_parent_child(events))
    findings.extend(_priv_esc_attempts(events))
    findings.extend(_persistence(events))

    impossible, skipped = _impossible_travel_placeholder(events)
    findings.extend(impossible)
    if skipped:
        skipped_checks.append(skipped)

    return findings, skipped_checks


def _auth_failure_burst(events: list[Event]) -> list[Finding]:
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for event in events:
        text = " ".join([to_lower_text(event.event_type), to_lower_text(event.action), to_lower_text(event.raw.get("message"))])
        if "auth" in text or "logon" in text or "login" in text:
            if "fail" in text or "denied" in text or "invalid" in text:
                grouped[(event.host or "unknown-host", event.user or "unknown-user")].append(event)

    findings: list[Finding] = []
    threshold = 5
    window = timedelta(minutes=5)
    for (host, user), items in grouped.items():
        ordered = sorted(items, key=lambda e: (e.timestamp is None, e.timestamp))
        for i in range(len(ordered)):
            start = ordered[i]
            if start.timestamp is None:
                continue
            burst = [start]
            for j in range(i + 1, len(ordered)):
                if ordered[j].timestamp and ordered[j].timestamp - start.timestamp <= window:
                    burst.append(ordered[j])
            if len(burst) >= threshold:
                findings.append(
                    Finding(
                        finding_id=f"F-AUTH-{host}-{user}",
                        title="Authentication failure burst",
                        description=f"{len(burst)} failed auth events within 5 minutes for {user} on {host}.",
                        confidence=0.8,
                        category="credential_access",
                        severity="high",
                        evidence=[b.evidence_ref() for b in burst[:10]],
                        related_entities={"host": [host], "user": [user]},
                    )
                )
                break
    return findings


def _encoded_powershell(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"powershell(\.exe)?\s+.*(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{8,}", re.IGNORECASE)
    for event in events:
        cmd = event.command_line or event.action or ""
        if pattern.search(cmd):
            findings.append(
                Finding(
                    finding_id=f"F-PS-{event.event_id}",
                    title="Encoded PowerShell execution",
                    description="Command line indicates encoded PowerShell payload execution.",
                    confidence=0.9,
                    category="execution",
                    severity="high",
                    evidence=[event.evidence_ref()],
                    related_entities={"host": [event.host] if event.host else [], "user": [event.user] if event.user else []},
                )
            )
    return findings


def _temp_process_exec(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    markers = ["\\appdata\\local\\temp\\", "/tmp/", "\\temp\\"]
    for event in events:
        target = to_lower_text(event.process) + " " + to_lower_text(event.command_line)
        if any(marker in target for marker in markers):
            findings.append(
                Finding(
                    finding_id=f"F-TEMP-{event.event_id}",
                    title="Process execution from temp directory",
                    description="Process or command line references temp directory execution path.",
                    confidence=0.7,
                    category="execution",
                    severity="medium",
                    evidence=[event.evidence_ref()],
                    related_entities={"host": [event.host] if event.host else [], "process": [event.process] if event.process else []},
                )
            )
    return findings


def _suspicious_parent_child(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        parent = to_lower_text(event.parent_process)
        child = to_lower_text(event.process)
        if parent and child and (parent, child) in SUSPICIOUS_PARENT_CHILD:
            findings.append(
                Finding(
                    finding_id=f"F-PC-{event.event_id}",
                    title="Suspicious parent-child process chain",
                    description=f"Observed atypical chain: {parent} -> {child}.",
                    confidence=0.85,
                    category="execution",
                    severity="high",
                    evidence=[event.evidence_ref()],
                    related_entities={"host": [event.host] if event.host else [], "process": [child, parent]},
                )
            )
    return findings


def _priv_esc_attempts(events: list[Event]) -> list[Finding]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        text = " ".join([to_lower_text(event.event_type), to_lower_text(event.action), to_lower_text(event.raw.get("message"))])
        if "privilege" in text or "sudo" in text or "elevation" in text:
            if "fail" in text or "denied" in text or "not allowed" in text:
                grouped[event.user or "unknown-user"].append(event)

    findings: list[Finding] = []
    for user, items in grouped.items():
        if len(items) >= 3:
            findings.append(
                Finding(
                    finding_id=f"F-PRIV-{user}",
                    title="Repeated privilege escalation attempts",
                    description=f"{len(items)} failed privilege escalation attempts detected for {user}.",
                    confidence=0.75,
                    category="privilege_escalation",
                    severity="high",
                    evidence=[event.evidence_ref() for event in items[:10]],
                    related_entities={"user": [user]},
                )
            )
    return findings


def _persistence(events: list[Event]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        text = " ".join([to_lower_text(event.event_type), to_lower_text(event.action), to_lower_text(event.raw.get("message"))])
        if any(keyword in text for keyword in PERSISTENCE_KEYWORDS):
            findings.append(
                Finding(
                    finding_id=f"F-PERSIST-{event.event_id}",
                    title="Potential persistence indicator",
                    description="Event content matched known persistence technique keywords.",
                    confidence=0.65,
                    category="persistence",
                    severity="medium",
                    evidence=[event.evidence_ref()],
                    related_entities={"host": [event.host] if event.host else [], "user": [event.user] if event.user else []},
                )
            )
    return findings


def _impossible_travel_placeholder(events: list[Event]) -> tuple[list[Finding], str | None]:
    geo_fields_present = any(
        e.raw.get("lat") is not None and e.raw.get("lon") is not None and e.timestamp is not None and e.user
        for e in events
    )
    if not geo_fields_present:
        return [], "Impossible-travel check skipped (no geo coordinates in input logs)."
    return [], None


def extract_iocs(events: list[Event]) -> dict[str, list[str]]:
    ip_values = sorted({e.ip for e in events if e.ip})
    hash_values = sorted({e.file_hash for e in events if e.file_hash})
    domains: set[str] = set()
    for event in events:
        for key in ("domain", "dns_query", "hostname"):
            value = event.raw.get(key)
            if isinstance(value, str) and "." in value and " " not in value:
                domains.add(value.lower())
    return {"ips": ip_values, "file_hashes": hash_values, "domains": sorted(domains)}
