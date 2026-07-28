from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Event:
    event_id: str
    timestamp: datetime | None
    host: str | None
    source: str
    user: str | None
    process: str | None
    action: str | None
    event_type: str | None
    severity: str | None
    ip: str | None = None
    file_hash: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    file_path: str | None = None
    line_number: int | None = None

    def evidence_ref(self) -> str:
        if self.file_path is None:
            return self.event_id
        if self.line_number is None:
            return f"{self.file_path}"
        return f"{self.file_path}:{self.line_number}"


@dataclass
class Finding:
    finding_id: str
    title: str
    description: str
    confidence: float
    category: str
    severity: str
    evidence: list[str]
    related_entities: dict[str, list[str]]

    @property
    def confidence_label(self) -> str:
        if self.confidence >= 0.85:
            return "high"
        if self.confidence >= 0.6:
            return "medium"
        return "low"
