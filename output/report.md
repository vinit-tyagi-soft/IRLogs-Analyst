# Incident Investigation Report

## Executive Summary
Analyzed 14 events and identified 7 notable findings. Highest-confidence issue: Encoded PowerShell execution (confidence 0.90).

## Scope / Input Stats
- Events analyzed: 14
- Findings: 7
- Event types: {'authentication': 6, 'process_execution': 2, 'privilege_escalation': 3, 'syslog': 3}
- Severity distribution: {'warning': 8, 'info': 1, 'high': 1, 'medium': 1, 'unknown': 3}
- Skipped check: Impossible-travel check skipped (no geo coordinates in input logs).

## Timeline Highlights
- Timeline window: 2026-07-25 10:00:00 -> 2026-07-25 10:22:00
- Distinct hosts observed: 1
- Distinct users observed: 1
- Top signal: Encoded PowerShell execution (high confidence)
- Top signal: Suspicious parent-child process chain (high confidence)
- Top signal: Authentication failure burst (medium confidence)

## Correlated Evidence Graph Summary
- host:workstation-7 <-> user:alice (co-occurred 11 times)
- user:alice <-> ip:203.0.113.10 (co-occurred 10 times)
- host:workstation-7 <-> process:powershell.exe (co-occurred 4 times)
- process:powershell.exe <-> file_hash:5f4dcc3b5aa765d61d8327deb882cf99 (co-occurred 1 times)
- host:workstation-7 <-> process:C:\Users\alice\AppData\Local\Temp\updater.exe (co-occurred 1 times)

## Key Findings (What / How / Why)
### Encoded PowerShell execution
- Confidence: 0.9 (high)
- Category: execution | Severity: high
- Description: Command line indicates encoded PowerShell payload execution.
- Evidence: /Users/vinit/IRLogs Analyst/sample_data/process.csv:2
### Suspicious parent-child process chain
- Confidence: 0.85 (high)
- Category: execution | Severity: high
- Description: Observed atypical chain: winword.exe -> powershell.exe.
- Evidence: /Users/vinit/IRLogs Analyst/sample_data/process.csv:2
### Authentication failure burst
- Confidence: 0.8 (medium)
- Category: credential_access | Severity: high
- Description: 5 failed auth events within 5 minutes for alice on workstation-7.
- Evidence: /Users/vinit/IRLogs Analyst/sample_data/auth.jsonl:1, /Users/vinit/IRLogs Analyst/sample_data/auth.jsonl:2, /Users/vinit/IRLogs Analyst/sample_data/auth.jsonl:3, /Users/vinit/IRLogs Analyst/sample_data/auth.jsonl:4, /Users/vinit/IRLogs Analyst/sample_data/auth.jsonl:5
### Repeated privilege escalation attempts
- Confidence: 0.75 (medium)
- Category: privilege_escalation | Severity: high
- Description: 3 failed privilege escalation attempts detected for alice.
- Evidence: /Users/vinit/IRLogs Analyst/sample_data/process.csv:4, /Users/vinit/IRLogs Analyst/sample_data/process.csv:5, /Users/vinit/IRLogs Analyst/sample_data/process.csv:6
### Process execution from temp directory
- Confidence: 0.7 (medium)
- Category: execution | Severity: medium
- Description: Process or command line references temp directory execution path.
- Evidence: /Users/vinit/IRLogs Analyst/sample_data/process.csv:3
### Potential persistence indicator
- Confidence: 0.65 (medium)
- Category: persistence | Severity: medium
- Description: Event content matched known persistence technique keywords.
- Evidence: /Users/vinit/IRLogs Analyst/sample_data/system.log:1
### Potential persistence indicator
- Confidence: 0.65 (medium)
- Category: persistence | Severity: medium
- Description: Event content matched known persistence technique keywords.
- Evidence: /Users/vinit/IRLogs Analyst/sample_data/system.log:2

## IOCs Extracted
- IPs: 203.0.113.10
- File hashes: 5f4dcc3b5aa765d61d8327deb882cf99
- Domains: None

## Unanswered Questions
- Were endpoint EDR alerts, DNS logs, and proxy logs available for cross-validation?
