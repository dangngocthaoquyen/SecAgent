"""Dataset, ASI03 contract, and ASI03/ASI05 policy routes for Workflow API."""

import secrets
from urllib.parse import unquote

from flask import jsonify, request
from pydantic import ValidationError

from workflow.asi03_contracts import ASI03ContractDraft, ASI03TargetPolicyDraft
from workflow.asi05_policy import ASI05PolicyDraft
from workflow.catalog import read_json
from workflow.dataset_normalizer import DatasetValidationError, normalize_dataset


def register_dataset_policy_routes(app, ctx) -> None:
    """Register dataset library, ASI03 contract, and ASI03/ASI05 policy routes."""

    nonce = ctx.nonce
    dataset_repo = ctx.dataset_repo
    asi03_contracts = ctx.asi03_contracts
    asi03_policies = ctx.asi03_policies
    asi05_policies = ctx.asi05_policies
    fail = ctx.fail
    operator_authorized = ctx.operator_authorized

    def dataset_auth():
        if not operator_authorized():
            return fail("operator_authentication_required", 403)
        supplied = request.headers.get("X-SecAgent-Validation", "")
        if not secrets.compare_digest(supplied, nonce):
            return fail("validation_nonce_required", 403)
        return None

    @app.get("/api/testing/datasets")
    def list_datasets():
        denied = dataset_auth()
        if denied:
            return denied
        summaries = [s.model_dump(mode="json") for s in dataset_repo.list_datasets()]
        return jsonify(workflow_schema_version="1.0.0", datasets=summaries)

    @app.post("/api/testing/datasets/validate")
    def validate_dataset():
        denied = dataset_auth()
        if denied:
            return denied
        try:
            raw_data = request.get_data()
            filename = unquote(request.headers.get("X-Dataset-Filename", "dataset.json"))
            envelope = normalize_dataset(raw_data, filename=filename)
            return jsonify(workflow_schema_version="1.0.0", valid=True, dataset=envelope.model_dump(mode="json"))
        except DatasetValidationError as exc:
            return fail(exc.code, 400)
        except Exception:
            return fail("invalid_dataset", 400)

    @app.post("/api/testing/datasets/import")
    def import_dataset():
        denied = dataset_auth()
        if denied:
            return denied
        try:
            raw_data = request.get_data()
            filename = unquote(request.headers.get("X-Dataset-Filename", "dataset.json"))
            envelope = normalize_dataset(raw_data, filename=filename)
            saved, created = dataset_repo.save_dataset(envelope)
            return (
                jsonify(workflow_schema_version="1.0.0", dataset=saved.model_dump(mode="json"), created=created),
                (201 if created else 200),
            )
        except DatasetValidationError as exc:
            return fail(exc.code, 400)
        except Exception:
            return fail("import_failed", 500)

    @app.get("/api/testing/datasets/<dataset_id>")
    def get_dataset(dataset_id):
        denied = dataset_auth()
        if denied:
            return denied
        envelope = dataset_repo.get_dataset(dataset_id)
        if envelope is None:
            return fail("dataset_not_found", 404)
        return jsonify(workflow_schema_version="1.0.0", dataset=envelope.model_dump(mode="json"))

    def _register_policy_group(store, prefix: str, draft_cls, url_prefix: str) -> None:
        missing_code = f"{prefix}_managed_catalog_required"

        def policy_draft():
            denied = dataset_auth()
            if denied:
                return denied
            if store is None:
                return fail(missing_code, 403)
            try:
                draft = draft_cls.model_validate(read_json(request.get_data()))
                return jsonify(workflow_schema_version="1.0.0", policy=store.create(draft)), 201
            except ValidationError:
                return fail(f"{prefix}_policy_fields_required", 400)
            except ValueError as exc:
                return fail(str(exc) if str(exc).startswith(f"{prefix}_") else f"{prefix}_policy_invalid", 400)

        def policy_lookup(target_id):
            denied = dataset_auth()
            if denied:
                return denied
            if store is None:
                return fail(missing_code, 403)
            return jsonify(workflow_schema_version="1.0.0", policy=store.for_target(target_id))

        def policy_read(policy_id):
            denied = dataset_auth()
            if denied:
                return denied
            if store is None:
                return fail(missing_code, 403)
            record = store.load(policy_id)
            if record is None:
                return fail(f"{prefix}_policy_unavailable", 404)
            return jsonify(workflow_schema_version="1.0.0", policy=store.status(record))

        def policy_review(policy_id):
            denied = dataset_auth()
            if denied:
                return denied
            if store is None:
                return fail(missing_code, 403)
            try:
                row = read_json(request.get_data())
                if set(row) != {"expected_revision_sha256", "review_confirmed"} or type(row["review_confirmed"]) is not bool:
                    raise ValueError(f"{prefix}_policy_review_confirmation_or_revision_required")
                record = store.review(policy_id, row["expected_revision_sha256"], confirmed=row["review_confirmed"])
                return jsonify(workflow_schema_version="1.0.0", policy=record)
            except (ValueError, TypeError, KeyError) as exc:
                code = str(exc) if str(exc).startswith(f"{prefix}_") else f"{prefix}_policy_review_rejected"
                return fail(code, 409)

        app.add_url_rule(f"{url_prefix}/drafts", endpoint=f"{prefix}_policy_draft", view_func=policy_draft, methods=["POST"])
        app.add_url_rule(f"{url_prefix}/target/<target_id>", endpoint=f"{prefix}_policy_lookup", view_func=policy_lookup, methods=["GET"])
        app.add_url_rule(f"{url_prefix}/<policy_id>", endpoint=f"{prefix}_policy_read", view_func=policy_read, methods=["GET"])
        app.add_url_rule(f"{url_prefix}/<policy_id>/review", endpoint=f"{prefix}_policy_review", view_func=policy_review, methods=["POST"])

    _register_policy_group(asi03_policies, "asi03", ASI03TargetPolicyDraft, "/api/testing/asi03-policies")
    _register_policy_group(asi05_policies, "asi05", ASI05PolicyDraft, "/api/testing/asi05-policies")

    @app.post("/api/testing/asi03-contracts/drafts")
    def asi03_draft():
        denied = dataset_auth()
        if denied:
            return denied
        if asi03_contracts is None:
            return fail("asi03_managed_catalog_required", 403)
        try:
            draft = ASI03ContractDraft.model_validate(read_json(request.get_data()))
            return jsonify(workflow_schema_version="1.0.0", contract=asi03_contracts.create(draft)), 201
        except ValidationError:
            return fail("asi03_contract_invalid", 400)
        except ValueError as exc:
            return fail(str(exc) if str(exc).startswith("asi03_") else "asi03_contract_invalid", 400)

    @app.get("/api/testing/asi03-contracts/<contract_id>")
    def asi03_read(contract_id):
        denied = dataset_auth()
        if denied:
            return denied
        if asi03_contracts is None:
            return fail("asi03_managed_catalog_required", 403)
        record = asi03_contracts.load(contract_id)
        if record is None:
            return fail("asi03_contract_unavailable", 404)
        return jsonify(workflow_schema_version="1.0.0", contract=asi03_contracts.status(record))

    @app.get("/api/testing/asi03-contracts/lookup/<dataset_id>/<case_id>/<target_id>")
    def asi03_lookup(dataset_id, case_id, target_id):
        denied = dataset_auth()
        if denied:
            return denied
        if asi03_contracts is None:
            return fail("asi03_managed_catalog_required", 403)
        record = asi03_contracts.for_case(dataset_id, case_id, target_id)
        return jsonify(workflow_schema_version="1.0.0", contract=record)

    @app.post("/api/testing/asi03-contracts/<contract_id>/review")
    def asi03_review(contract_id):
        denied = dataset_auth()
        if denied:
            return denied
        if asi03_contracts is None:
            return fail("asi03_managed_catalog_required", 403)
        try:
            row = read_json(request.get_data())
            if set(row) != {"expected_revision_sha256", "review_confirmed"} or type(row["review_confirmed"]) is not bool:
                raise ValueError("asi03_review_confirmation_or_revision_required")
            record = asi03_contracts.review(contract_id, row["expected_revision_sha256"], confirmed=row["review_confirmed"])
            return jsonify(workflow_schema_version="1.0.0", contract=record)
        except (ValueError, TypeError, KeyError) as exc:
            code = str(exc) if str(exc).startswith("asi03_") else "asi03_review_rejected"
            return fail(code, 409)
