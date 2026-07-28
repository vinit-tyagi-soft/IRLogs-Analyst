# IRLogs-Analyst

`irlogs-analyst` is a practical Python CLI for incident responders. It ingests mixed log formats, normalizes them into a shared event model, correlates entities across sources, applies transparent detection rules, and generates investigation reports in Markdown + JSON.

## Features

- Recursive ingestion from files/directories.
- Supported formats:
  - JSON / JSONL
  - CSV / TSV
  - Plain text (including basic syslog-style parsing)
  - EVTX (if optional `python-evtx` dependency is installed)
- Shared normalized event model:
  - `timestamp`, `host`, `source`, `user`, `process`, `action`, `event_type`, `severity`, `raw`
  - plus `ip`, `file_hash`, `parent_process`, `command_line`, and evidence references
- Correlation by host/user/process/IP/hash with simple evidence graph summary.
- Deterministic offline rules for suspicious activity:
  - Auth failure bursts
  - Encoded PowerShell execution
  - Process execution from temp directories
  - Suspicious parent-child process chains
  - Repeated privilege escalation attempts
  - Persistence indicators
  - Impossible travel placeholder (skips gracefully if geo data absent)
- Reporting output:
  - `report.md`
  - `report.json`
- Optional AI narrative summary:
  - Enabled only via CLI flag
  - Uses `OPENAI_API_KEY` if available
  - Safe fallback to deterministic summary if unavailable/fails

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional EVTX support:

```bash
pip install python-evtx
```

## Usage

Run against one or more files/folders:

```bash
python -m irlogs_analyst sample_data --output-dir output --write-normalized
```

Enable optional AI summary:

```bash
export OPENAI_API_KEY="your_key"
python -m irlogs_analyst sample_data --output-dir output --use-ai-summary
```

## Investigation Workflow

1. Collect IR artifacts from endpoints, auth providers, EDR, and network infrastructure.
2. Place all logs under one or more folders.
3. Run `irlogs-analyst` recursively on those paths.
4. Review `report.md` for executive narrative and findings.
5. Use `report.json` + `normalized_events.json` for deep pivoting and automation.
6. Validate findings manually against source evidence references.

## Sample Dataset

`sample_data/` includes mixed-format logs intentionally containing:

- Failed login burst
- Encoded PowerShell command
- Temp directory execution
- Suspicious parent-child chain (`winword.exe -> powershell.exe`)
- Repeated privilege escalation denials
- Persistence-like log messages

Expected result notes when running on sample:

- Multiple high/medium findings should be produced.
- Impossible-travel should be reported as skipped due to missing geo fields.
- Markdown and JSON reports should be created in the output directory.

## Tests

```bash
pytest -q
```

Current tests cover:

- JSONL ingestion + normalization basics
- Auth failure burst rule detection and impossible-travel graceful skip behavior

## Limitations / Assumptions

- Parsing relies on common field names and heuristics; highly custom schemas may need adapters.
- Syslog parsing is intentionally lightweight and best-effort.
- Correlation graph is summary-level, not a full graph database.
- Impossible-travel is a placeholder check that requires geo coordinates in events.
- AI summary is optional and non-blocking; deterministic logic remains the source of truth.
