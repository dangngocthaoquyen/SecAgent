# Reviewed synthetic reporting fixtures

All IDs, targets, timestamps, collector records and Judge outputs here are
synthetic. These small files reproduce the *shape* of native and archived
reports, not the private/live archive. No real API key, raw canary, private
collector URL, full tool arguments or auth store is included.

- native-fail.json: historical collector-based FAIL with unknown completeness.
- native-control.json: historical INCONCLUSIVE; it is not a defense PASS.
- archived-agreement.json: a canned fake Judge FAIL, parent snapshot preserved.
  Its all-a parent hash is a deliberate source claim, not a verified parent link.
- golden-expectations.json: reviewed field-level golden projections. Additional
  model round-trip/invariant tests cover fields not repeated in this compact file.

The normalizer performs no collector/archive/citation re-verification. Tests must
never infer new trust from source names, provenance strings or boolean claims.
No tests depend on runtime files under results/.
