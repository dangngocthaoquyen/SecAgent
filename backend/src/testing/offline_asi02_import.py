"""Backward-compatible wrapper delegating to generic `testing.offline_stored_import`."""

from __future__ import annotations

import sys

from testing.offline_stored_import import (
    BLIND_DATASET_FILENAME,
    FORBIDDEN_BLIND_KEYS,
    HISTORICAL_DATASET_FILENAME,
    BlindDatasetSummary,
    BlindEvaluationDataset,
    BlindEvaluationRecord,
    BlindStoredEvidence,
    DsmlIntentSignal,
    HistoricalComparisonDataset,
    HistoricalComparisonRecord,
    HistoricalDatasetSummary,
    OfflineImportResult,
    StoredRecordProvenance,
    assert_no_blind_leakage,
    build_offline_stored_datasets,
    detect_dsml_intent,
    export_offline_stored_datasets,
    main as _generic_main,
    redact_secrets_preserving_content,
)


def main(argv: list[str] | None = None) -> int:
    return _generic_main(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
