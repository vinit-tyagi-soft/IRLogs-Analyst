from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any, Iterator


def discover_files(inputs: list[str]) -> list[Path]:
    files: list[Path] = []
    for input_path in inputs:
        path = Path(input_path).expanduser().resolve()
        if path.is_file():
            files.append(path)
            continue
        if path.is_dir():
            files.extend([p for p in path.rglob("*") if p.is_file()])
    return files


def ingest_file(path: Path) -> Iterator[tuple[dict[str, Any], int]]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        yield from _ingest_json(path)
    elif suffix == ".jsonl":
        yield from _ingest_jsonl(path)
    elif suffix in {".csv", ".tsv"}:
        yield from _ingest_delimited(path, "\t" if suffix == ".tsv" else ",")
    elif suffix == ".evtx":
        yield from _ingest_evtx(path)
    else:
        yield from _ingest_text(path)


def _ingest_json(path: Path) -> Iterator[tuple[dict[str, Any], int]]:
    content = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    if isinstance(content, list):
        for idx, row in enumerate(content, start=1):
            if isinstance(row, dict):
                yield row, idx
    elif isinstance(content, dict):
        records = content.get("records")
        if isinstance(records, list):
            for idx, row in enumerate(records, start=1):
                if isinstance(row, dict):
                    yield row, idx
        else:
            yield content, 1


def _ingest_jsonl(path: Path) -> Iterator[tuple[dict[str, Any], int]]:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for idx, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                if isinstance(row, dict):
                    yield row, idx
            except json.JSONDecodeError:
                continue


def _ingest_delimited(path: Path, delimiter: str) -> Iterator[tuple[dict[str, Any], int]]:
    with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=delimiter)
        for idx, row in enumerate(reader, start=2):
            yield dict(row), idx


SYSLOG_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+(?P<source>[A-Za-z0-9_\-/\.]+)(?:\[\d+\])?:\s+(?P<message>.*)$"
)


def _ingest_text(path: Path) -> Iterator[tuple[dict[str, Any], int]]:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for idx, line in enumerate(handle, start=1):
            message = line.strip()
            if not message:
                continue
            match = SYSLOG_RE.match(message)
            if match:
                yield {
                    "timestamp": match.group("timestamp"),
                    "host": match.group("host"),
                    "source": match.group("source"),
                    "message": match.group("message"),
                    "event_type": "syslog",
                }, idx
            else:
                yield {"message": message, "event_type": "text_log"}, idx


def _ingest_evtx(path: Path) -> Iterator[tuple[dict[str, Any], int]]:
    try:
        from Evtx.Evtx import Evtx  # type: ignore
        import xml.etree.ElementTree as ET
    except Exception:
        return

    with Evtx(str(path)) as log:
        for idx, record in enumerate(log.records(), start=1):
            try:
                xml_root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue
            row: dict[str, Any] = {"event_type": "windows_evtx"}
            system = xml_root.find(".//{*}System")
            if system is not None:
                for child in system:
                    tag = child.tag.split("}")[-1]
                    if child.attrib:
                        row[tag] = child.attrib
                    elif child.text:
                        row[tag] = child.text
            eventdata = xml_root.find(".//{*}EventData")
            if eventdata is not None:
                for data in eventdata:
                    key = data.attrib.get("Name", "EventData")
                    row[key] = data.text
            yield row, idx
