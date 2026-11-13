"""Opt-in local archive checks. No target, evaluator, provider or network imports."""
import csv
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path
import re
import stat

from reporting.models import ArchiveVerification, ArtifactCheck, Model, ExecutionReport, ArchivedAssessmentReport
from reporting.normalizers import normalize_report_bytes, NormalizationError
from reporting.redaction import Redactor

MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_INVENTORY_BYTES = 64 * 1024
MAX_EVENTS = 10000


class ArchiveVerificationError(ValueError):
    """Unsafe selection or malformed inventory; messages never contain raw input."""


class VerifiedArchive(Model):
    verification: ArchiveVerification
    execution: ExecutionReport | None = None
    assessment: ArchivedAssessmentReport | None = None


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _no_links(path):
    for node in [*reversed(path.parents), path]:
        try:
            info = node.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ArchiveVerificationError("Symlink or reparse-point access rejected.")


class ArchiveReader:
    """Explicit root, bounded regular-file reads; does not follow source report paths."""
    def __init__(self, root):
        if str(root).startswith(("\\\\", "//")):
            raise ArchiveVerificationError("Network archive roots are not supported.")
        self.root = Path(root).absolute()
        if ".." in self.root.parts:
            raise ArchiveVerificationError("Unsafe archive root.")
        _no_links(self.root)
        if not self.root.is_dir():
            raise ArchiveVerificationError("Archive root unavailable.")

    def path(self, selected, *, absolute=False):
        path = Path(selected)
        if ".." in path.parts or ":" in str(path).replace(path.drive, ""):
            raise ArchiveVerificationError("Unsafe artifact path.")
        if path.is_absolute():
            if not absolute:
                raise ArchiveVerificationError("Select artifacts relative to the archive root.")
        else:
            if path.drive or path.root:
                raise ArchiveVerificationError("Unsafe artifact path.")
            path = self.root / path
        try:
            path.relative_to(self.root)
        except ValueError:
            raise ArchiveVerificationError("Artifact outside selected archive root.") from None
        _no_links(path)
        return path

    def read(self, path, limit=MAX_ARTIFACT_BYTES):
        _no_links(path)
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(info.st_mode):
            raise ArchiveVerificationError("Artifact is not a regular file.")
        if info.st_size > limit:
            raise ArchiveVerificationError("Artifact exceeds size limit.")
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ArchiveVerificationError("Artifact exceeds size limit.")
        # Detect common concurrent changes; an immutable operator-controlled root is required.
        after = path.lstat()
        if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ArchiveVerificationError("Artifact changed during read.")
        return raw


def _json(raw):
    def pairs(items):
        row = {}
        for k, v in items:
            if k in row:
                raise ValueError("Duplicate key")
            row[k] = v
        return row
    def reject(_):
        raise ValueError("Nonfinite number")
    return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=pairs, parse_constant=reject)


def _inventory(raw, reader, expected):
    try:
        rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"), newline=""), strict=True))
        if not rows or rows[0] != ["Path", "Hash"] or len(rows) != 5:
            raise ValueError()
        found = {}
        for row in rows[1:]:
            if len(row) != 2 or not re.fullmatch(r"[a-fA-F0-9]{64}", row[1]):
                raise ValueError()
            path = reader.path(row[0], absolute=True)
            key = str(path).casefold()
            if key in found:
                raise ValueError()
            found[key] = row[1].lower()
        if set(found) != {str(p).casefold() for p in expected.values()}:
            raise ValueError()
        return found
    except (UnicodeError, csv.Error, ValueError):
        raise ArchiveVerificationError("Malformed, duplicate or unexpected inventory entries.") from None


def _aggregate(states):
    for state in ("mismatch", "missing", "unsupported", "not_performed"):
        if state in states:
            return state
    return "verified"


def _timestamp(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError()
    return parsed


def _evidence(raws, document):
    """Verify relationships among stored records, never historical network authenticity."""
    checks = {}
    def check(name, condition):
        checks[name] = "verified" if condition else "mismatch"
    try:
        manifest = _json(raws["manifest"])
        export = _json(raws["collector_export"])
        lines = raws["events"].decode("utf-8-sig").splitlines()
        if len(lines) > MAX_EVENTS or any(not line.strip() for line in lines):
            raise ValueError()
        events = [_json(line.encode("utf-8")) for line in lines]
        if type(manifest.get("schema")) is not int or manifest.get("schema") != 1 or manifest.get("condition") != "attack":
            return {"evidence_format": "unsupported"}, {}
        if not all(isinstance(manifest.get(k), str) and re.fullmatch(r"[a-f0-9]{32}", manifest[k]) for k in ("run_id", "canary")):
            raise ValueError()
        keys = {"schema", "kind", "method", "run_id", "collector_id", "canary_sha256", "peer_matches", "timestamp"}
        if any(not isinstance(e, dict) or set(e) != keys or type(e["schema"]) is not int or e["schema"] != 1
               or e["kind"] not in {"page", "receipt"} or e["method"] not in {"GET", "POST"}
               or type(e["peer_matches"]) is not bool for e in events):
            raise ValueError()
        evaluation = document["evaluation"]
        if evaluation.get("testcase_id") != "GH-WEB-001" or document.get("category") != "goal_hijacking":
            return {"evidence_profile": "unsupported"}, {}
        items = [e for e in evaluation["observation"]["evidence"] if e.get("kind") == "collector_receipt"]
        if len(items) != 1:
            return {"collector_report_reference": "missing" if not items else "unsupported"}, {}
        item = items[0]
        claim = item["data"]
        run = manifest["run_id"]
        collector = "canary-" + run
        canonical = _sha(json.dumps(events, sort_keys=True).encode("utf-8"))
        check("collector_export", export.get("records") == events and export.get("run_id") == run)
        check("correlation", claim.get("run_id") == run and claim.get("collector_id") == collector
              and all(e["run_id"] == run and e["collector_id"] == collector
                      and e["canary_sha256"] == _sha(manifest["canary"].encode("utf-8")) for e in events))
        check("target_identity", manifest.get("target_id") == evaluation.get("target_id"))
        check("fixture_condition_claim", claim.get("condition") == manifest.get("condition"))
        check("collector_reference", item.get("source") == "local_collector" and item.get("name") == collector
              and item.get("reference") == "collector." + run)
        checks["collector_provenance_recorded"] = ("missing" if not claim.get("provenance") else
            "verified" if claim["provenance"] == "independent_local_collector" else "unsupported")
        check("collector_canonical_digest", claim.get("log_sha256") == canonical)
        check("manifest_digest_claim", claim.get("manifest_sha256") == _sha(raws["manifest"]))
        pages = [e for e in events if e["kind"] == "page" and e["method"] == "GET"]
        receipts = [e for e in events if e["kind"] == "receipt"]
        checks["page_event"] = "verified" if pages else "missing"
        checks["callback_receipt"] = "verified" if receipts else "missing"
        check("receipt_count", type(claim.get("receipt_count")) is int and claim["receipt_count"] == len(receipts))
        check("peer_match_recorded", bool(events) and all(e["peer_matches"] is True for e in events))
        times = [_timestamp(e["timestamp"]) for e in events]
        created, reported = _timestamp(manifest["created_at"]), _timestamp(evaluation["timestamp"])
        check("event_ordering", bool(times) and times == sorted(times) and all(created <= t <= reported for t in times)
              and all(any(_timestamp(p["timestamp"]) <= _timestamp(e["timestamp"])
                          and events.index(p) < events.index(e) for p in pages) for e in receipts))
        check("receipt_claims", bool(receipts) and claim.get("observed_method") == receipts[0]["method"]
              and claim.get("receipt_timestamp") == receipts[0]["timestamp"])
        check("positive_collector_claims", item.get("success") is True and claim.get("correlation_valid") is True
              and claim.get("page_served") is True and bool(receipts) and bool(pages))
        return checks, dict(fixture_correlation_ref=Redactor().identifier(run), receipt_count=len(receipts),
                           observed_methods=sorted({e["method"] for e in receipts}),
                           computed_collector_canonical_sha256=canonical)
    except (KeyError, TypeError, ValueError, AttributeError, UnicodeError):
        return {**checks, "evidence_format": "unsupported"}, {}


def verify_archive(root, *, inventory, execution, assessment=None):
    """All selections are root-relative; absolute paths only inside the legacy CSV.

    A verified result describes these local bytes/relationships, not the security verdict.
    The assessment must also be inside root, which may be an explicit common archive parent.
    """
    reader = ArchiveReader(root)
    inventory_path, execution_path = reader.path(inventory), reader.path(execution)
    base = inventory_path.parent
    expected = {"manifest": base / "fixture/manifest.json", "events": base / "fixture/events.jsonl",
                "collector_export": base / "sanitized-collector-after.json", "execution": execution_path}
    # Validate every derived path before any read, including intermediate directories.
    for path in expected.values():
        reader.path(path, absolute=True)
    inventory_bytes = reader.read(inventory_path, MAX_INVENTORY_BYTES)
    hashes = _inventory(inventory_bytes, reader, expected) if inventory_bytes is not None else None
    checks = [ArtifactCheck(artifact_role="inventory", state="missing" if inventory_bytes is None else "not_performed",
                           actual_file_byte_sha256=_sha(inventory_bytes) if inventory_bytes is not None else None,
                           size_bytes=len(inventory_bytes) if inventory_bytes is not None else None)]
    raws = {}
    for role, path in expected.items():
        raw = reader.read(path)
        expected_hash = hashes.get(str(path).casefold()) if hashes else None
        actual = _sha(raw) if raw is not None else None
        state = "missing" if raw is None else "not_performed" if expected_hash is None else "verified" if actual == expected_hash else "mismatch"
        checks.append(ArtifactCheck(artifact_role=role, state=state, expected_file_byte_sha256=expected_hash,
                                   actual_file_byte_sha256=actual, size_bytes=len(raw) if raw is not None else None))
        if raw is not None:
            raws[role] = raw
    native = None
    document = None
    redact_values = ()
    if "manifest" in raws:
        try:
            canary = _json(raws["manifest"]).get("canary")
            if isinstance(canary, str) and canary:
                redact_values = (canary,)
        except (ValueError, UnicodeError, AttributeError):
            pass  # Evidence format is reported separately; never treat malformed metadata as configuration.
    if "execution" in raws:
        try:
            native = normalize_report_bytes(raws["execution"], redact_values=redact_values)
            document = _json(raws["execution"])
            if not isinstance(native, ExecutionReport):
                raise ValueError()
        except (NormalizationError, ValueError, UnicodeError):
            raise ArchiveVerificationError("Unsupported execution artifact.") from None
    integrity = "missing" if hashes is None else _aggregate([c.state for c in checks[1:]])
    evidence_checks, details = ({"required_artifacts": "missing"}, {}) if len(raws) != 4 else _evidence(raws, document)
    crosscheck = "not_performed"
    archived = None
    if assessment is not None:
        assessment_bytes = reader.read(reader.path(assessment))
        checks.append(ArtifactCheck(artifact_role="assessment", state="missing" if assessment_bytes is None else "not_performed",
                                   actual_file_byte_sha256=_sha(assessment_bytes) if assessment_bytes is not None else None,
                                   size_bytes=len(assessment_bytes) if assessment_bytes is not None else None))
        crosscheck = "missing"
        if assessment_bytes is not None:
            try:
                archived = normalize_report_bytes(assessment_bytes, redact_values=redact_values)
                source = _json(assessment_bytes)
                if not isinstance(archived, ArchivedAssessmentReport):
                    raise ValueError()
                parent = source["original"]
                parent_id = parent.get("secagent_run_id")
                actual_id = document["evaluation"].get("run_id") if document else None
                if not parent_id or not actual_id or not parent.get("report_file_byte_sha256"):
                    crosscheck = "missing"
                else:
                    crosscheck = "verified" if parent_id == actual_id and parent["report_file_byte_sha256"] == _sha(raws["execution"]) else "mismatch"
                if document:
                    evaluation = document.get("evaluation", {})
                    snapshots = ((parent.get("deterministic_verdict"), (evaluation.get("deterministic_result") or {}).get("status")),
                                 (parent.get("final_verdict"), evaluation.get("final_verdict")))
                    evidence_checks["crosscheck_verdict_snapshots"] = (
                        "missing" if any(a is None or b is None for a, b in snapshots) else
                        "verified" if all(a == b for a, b in snapshots) else "mismatch")
                    identities = [(parent.get(key), evaluation.get(key, document.get(key))) for key in ("testcase_id", "target_id")]
                    evidence_checks["crosscheck_identity_claims"] = (
                        "missing" if any(a is None or b is None for a, b in identities) else
                        "verified" if all(a == b for a, b in identities) else "mismatch")
            except (NormalizationError, ValueError, KeyError, UnicodeError, TypeError):
                raise ArchiveVerificationError("Unsupported assessment artifact.") from None
            fixture_link = "missing"
            if "manifest" in raws:
                try:
                    fixture_id = _json(raws["manifest"]).get("run_id")
                    if fixture_id and parent.get("fixture_correlation_id"):
                        fixture_link = "verified" if parent["fixture_correlation_id"] == fixture_id else "mismatch"
                except (ValueError, UnicodeError, AttributeError):
                    fixture_link = "unsupported"
            evidence_checks["crosscheck_fixture_correlation"] = fixture_link
    internal = _aggregate([v for k, v in evidence_checks.items() if not k.startswith("crosscheck_")])
    verification = ArchiveVerification(file_integrity=integrity, internal_evidence_consistency=internal,
        collector_canonical_digest=evidence_checks.get("collector_canonical_digest", "not_performed"),
        crosscheck_linkage=crosscheck, artifacts=checks, checks=evidence_checks, **details)
    # New typed metadata only. The historical source/provenance/verdict blocks remain untouched.
    return VerifiedArchive(verification=verification,
        execution=native.model_copy(update={"artifact_verification": verification}) if native else None,
        assessment=archived.model_copy(update={"artifact_verification": verification}) if archived else None)
