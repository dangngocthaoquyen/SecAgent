"""Immutable, bounded local dataset records with original-byte verification."""
import base64
from hashlib import sha256
from pathlib import Path
import re
from threading import RLock
from reporting.artifacts import ArchiveReader, _no_links, _json
from workflow.batch import _write_atomic
from workflow.dataset_models import DatasetEnvelope, DatasetSummary
from workflow.dataset_normalizer import normalize_dataset, MAX_FILE_BYTES


class DatasetRepository:
    def __init__(self, root: Path):
        root = Path(root).absolute()
        if str(root).startswith((chr(92) * 2, "//")) or ".." in root.parts:
            raise ValueError("Dataset storage must be a local directory.")
        _no_links(root)
        self.root = root / "datasets"
        _no_links(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._reader = ArchiveReader(self.root)
        self._lock = RLock()

    def _safe_path(self, dataset_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", dataset_id):
            raise ValueError("Invalid dataset identifier.")
        return self._reader.path(f"{dataset_id}.json")

    def save_dataset(self, envelope: DatasetEnvelope) -> tuple[DatasetEnvelope, bool]:
        """Exact source bytes deduplicate; distinct bytes create immutable revisions."""
        original = envelope._source_bytes
        verified = normalize_dataset(original, envelope.name)
        if verified.content_sha256 != envelope.content_sha256:
            raise ValueError("Dataset content does not match original upload.")
        with self._lock:
            path = self._safe_path(envelope.dataset_id)
            if path.exists():
                existing = self.get_dataset(envelope.dataset_id)
                if existing is None or existing.file_sha256 != envelope.file_sha256:
                    raise ValueError("Existing dataset is invalid; replacement is forbidden.")
                return existing, False
            _write_atomic(path, {"storage_version": 1,
                "original_base64": base64.b64encode(original).decode("ascii"),
                "envelope": envelope.model_dump(mode="json")})
            return envelope, True

    def get_dataset(self, dataset_id: str) -> DatasetEnvelope | None:
        with self._lock:
            try:
                raw = self._reader.read(self._safe_path(dataset_id), MAX_FILE_BYTES * 5)
                if raw is None:
                    return None
                stored = _json(raw)
                if set(stored) != {"storage_version", "original_base64", "envelope"} or stored['storage_version'] != 1:
                    return None
                original = base64.b64decode(stored['original_base64'], validate=True)
                envelope = DatasetEnvelope.model_validate(stored['envelope'])
                if (envelope.dataset_id != dataset_id or sha256(original).hexdigest() != envelope.file_sha256
                        or envelope.computed_content_sha256() != envelope.content_sha256):
                    return None
                reconstructed = normalize_dataset(original, envelope.name)
                if reconstructed.content_sha256 != envelope.content_sha256:
                    return None
                envelope._source_bytes = original
                return envelope
            except (OSError, ValueError, TypeError, KeyError, RecursionError):
                return None

    def list_datasets(self) -> list[DatasetSummary]:
        with self._lock:
            _no_links(self.root)
            summaries = []
            for file_path in self.root.glob("*.json"):
                if not re.fullmatch(r"[a-f0-9]{32}\.json", file_path.name):
                    continue
                envelope = self.get_dataset(file_path.stem)
                if envelope is not None:
                    summaries.append(envelope.to_summary())
            return sorted(summaries, key=lambda s: s.imported_at, reverse=True)
