# SecAgent

AI Agent Security Testing Framework — Python prototype for PI, TM, SD and GH.

Week 5: [Member 2 handoff and run instructions](docs/week5-member2-handoff.md),
[testcase evaluation matrix](docs/testcase-evaluation-matrix.md), and
[external evaluation contract for Member 1](docs/week5-evaluation-contract.md).

Native execution defaults to rule-only. The existing Runner supports explicitly
configured HybridEvaluator fallback with a bounded Judge-call budget; live Judge
calls require separate opt-in. See [Runner Judge integration](docs/runner-judge-integration.md)
for configuration, offline tests and reporting limits.

