from pathlib import Path

from irlogs_analyst.ingest import ingest_file
from irlogs_analyst.normalize import normalize_record
from irlogs_analyst.rules import detect_findings


def test_jsonl_normalization(tmp_path: Path) -> None:
    sample = tmp_path / "sample.jsonl"
    sample.write_text(
        '{"timestamp":"2026-01-01T00:00:00Z","host":"h1","source":"auth","user":"u1","action":"login failed"}\n',
        encoding="utf-8",
    )
    rows = list(ingest_file(sample))
    assert len(rows) == 1
    record, line_number = rows[0]
    event = normalize_record(record, "id1", sample, line_number)
    assert event.host == "h1"
    assert event.user == "u1"
    assert event.timestamp is not None


def test_rule_detection_auth_burst(tmp_path: Path) -> None:
    sample = tmp_path / "sample.jsonl"
    lines = []
    for minute in range(5):
        lines.append(
            '{"timestamp":"2026-01-01T00:0%d:00Z","host":"h1","source":"auth","user":"u1","event_type":"authentication","action":"login failed"}'
            % minute
        )
    sample.write_text("\n".join(lines) + "\n", encoding="utf-8")
    events = []
    for idx, (record, line_number) in enumerate(ingest_file(sample), start=1):
        events.append(normalize_record(record, f"id{idx}", sample, line_number))

    findings, skipped = detect_findings(events)
    assert any(f.title == "Authentication failure burst" for f in findings)
    assert any("Impossible-travel check skipped" in item for item in skipped)
