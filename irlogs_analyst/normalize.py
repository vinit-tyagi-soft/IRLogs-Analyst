from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import Event
from .utils import first_non_empty, parse_timestamp, to_lower_text


def normalize_record(record: dict[str, Any], event_id: str, file_path: Path, line_number: int) -> Event:
    timestamp = parse_timestamp(
        first_non_empty(
            record,
            ["timestamp", "@timestamp", "time", "datetime", "event_time", "TimeCreated", "UtcTime"],
        )
    )
    host = _to_str(first_non_empty(record, ["host", "hostname", "computer", "Computer"]))
    source = _to_str(first_non_empty(record, ["source", "log_name", "provider", "channel"])) or "unknown"
    user = _to_str(first_non_empty(record, ["user", "username", "account", "TargetUserName", "SubjectUserName"]))
    process = _to_str(first_non_empty(record, ["process", "process_name", "Image", "ProcessName"]))
    parent_process = _to_str(first_non_empty(record, ["parent_process", "ParentImage", "ParentProcessName"]))
    action = _to_str(first_non_empty(record, ["action", "operation", "event_action", "Task", "message"]))
    event_type = _infer_event_type(record, action)
    severity = _to_str(first_non_empty(record, ["severity", "level", "log_level", "event_severity"]))
    ip = _to_str(first_non_empty(record, ["ip", "src_ip", "source_ip", "client_ip", "IpAddress"]))
    file_hash = _to_str(first_non_empty(record, ["hash", "file_hash", "sha256", "md5", "SHA256"]))
    command_line = _to_str(first_non_empty(record, ["command_line", "cmdline", "CommandLine"]))

    return Event(
        event_id=event_id,
        timestamp=timestamp,
        host=host,
        source=source,
        user=user,
        process=process,
        action=action,
        event_type=event_type,
        severity=severity,
        ip=ip,
        file_hash=file_hash,
        parent_process=parent_process,
        command_line=command_line,
        raw=record,
        file_path=str(file_path),
        line_number=line_number,
    )


def _to_str(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value).strip() or None


def _infer_event_type(record: dict[str, Any], action: str | None) -> str | None:
    explicit = first_non_empty(record, ["event_type", "event_name", "EventID", "event_id"])
    if explicit is not None:
        return str(explicit)

    text = " ".join(
        [
            to_lower_text(action),
            to_lower_text(record.get("message")),
            to_lower_text(record.get("Task")),
        ]
    )
    if "login" in text or "logon" in text or "authentication" in text:
        return "authentication"
    if "process" in text or "powershell" in text or "cmd.exe" in text:
        return "process_execution"
    if "privilege" in text or "sudo" in text or "elevation" in text:
        return "privilege_escalation"
    if "service" in text or "scheduled task" in text or "run key" in text:
        return "persistence"
    return None
