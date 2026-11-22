# SecAgent

## Start the local application

With Python and Node on `PATH`, install dependencies once and start all three
loopback services with:

```powershell
python -m pip install -r backend/requirements.txt -r backend/requirements-reporting.txt
Push-Location frontend
npm ci
Pop-Location
python start_secagent_local.py
```

The launcher opens the frontend and stops its own services on Ctrl+C. It
generates a private session credential in memory; the browser never asks for
an operator token. Target profiles persist in the user's local application
data. A target requires an explicit confirmation for its first benign probe,
and execution still requires a fresh, bounded grant. The default evaluation
mode is rule-only. See [local target management](docs/target-management.md).

AI Agent Security Testing Framework — Python prototype for PI, TM, SD and GH.

ASI03 Identity & Privilege Abuse and ASI05 Unexpected Code Execution now have
target-independent candidate YAML, matched controls, and network-free pipeline
tests. See [ASI03/ASI05 attack assets](docs/asi03-asi05-attack-development.md)
for required lab capabilities and evidence. No live DVAA finding is claimed.

Week 5: [Member 2 handoff and run instructions](docs/week5-member2-handoff.md),
[testcase evaluation matrix](docs/testcase-evaluation-matrix.md), and
[external evaluation contract for Member 1](docs/week5-evaluation-contract.md).

Native execution defaults to rule-only. The existing Runner supports explicitly
configured HybridEvaluator fallback with a bounded Judge-call budget; live Judge
calls require separate opt-in. See [Runner Judge integration](docs/runner-judge-integration.md)
for configuration, offline tests and reporting limits.

