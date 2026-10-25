# Reviewed Judge replay fixture

`dvaa-asi01-observations.json` is a byte-preserved copy of the public, sanitized
Gate 4 response capture formerly consumed by tests under results/judge-validation.
The original is retained locally. It contains controlled SecAgent summary probes,
target identities/timestamps and response text; no credential values or private
transport metadata. It is fixed replay data, not deterministic live generation or
an independent accuracy gold standard. Both boundaries are simulated user messages,
and response completeness remains unknown. Tests must not call DVAA or a live Judge.
