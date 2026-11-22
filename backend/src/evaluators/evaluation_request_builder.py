"""Build the existing v1.0 Judge request from trusted case data and observations."""

from hashlib import sha256
import json
import re
from uuid import uuid4

from core.models import Observation, TestCase
from core.models.asi05_execution import Asi05ExecutionRequest
from core.models.evidence import public_evidence_data
from evaluators.asi05_execution import build_execution_request
from integrations.external_evaluator.models import EvaluationRequest
from integrations.external_evaluator.skills import SkillBundleLoader


class JudgeInputRejected(ValueError):
    """Safe-to-report reason why reviewed input cannot be disclosed to a Judge."""


class EvaluationRequestBuilder:
    def __init__(self, bundle_loader: SkillBundleLoader | None = None) -> None:
        self._bundle_loader = bundle_loader or SkillBundleLoader()

    def build_execution(self, testcase: TestCase, observation: Observation) -> Asi05ExecutionRequest:
        """Build the separate deterministic ASI05 action request.

        Phase 1 does not send this request to Pi or reuse the response-only
        Markdown Skill for execution claims.
        """
        return build_execution_request(testcase, observation)

    def build(self, testcase: TestCase, observation: Observation, *,
              prepared_prompt: str | None = None,
              reviewed_input_sha256: str | None = None,
              sensitive_values: tuple[str, ...] = ()) -> EvaluationRequest:
        semantic = testcase.evaluation.semantic
        if semantic is None or not semantic.enabled or semantic.skill != testcase.category:
            raise ValueError("Semantic evaluation is not configured for this category.")

        context = semantic.trusted_context.copy()
        # The rendered public source can be changed by the trusted testcase caller.
        if "source_text" in context and "project_description" in testcase.variables:
            context["source_text"] = testcase.variables["project_description"]

        # Disclosure is opt-in from the reviewed text binding, never from target
        # metadata. The digest binds permission to the exact input sent this run.
        input_fields = {}
        if reviewed_input_sha256 is not None:
            if (testcase.id not in {"GH-C01", "GH-001", "GH-002"}
                    or testcase.category != "goal_hijacking"
                    or not testcase.evaluation.rules
                    or any(rule.type not in {"marker", "regex"} for rule in testcase.evaluation.rules)
                    or not {"original_goal", "attacker_goal", "source_text", "trust_boundary"} <= context.keys()
                    or any(key in context for key in (
                        "required_fetch_url", "required_trace_scope", "collector_verification_required"))):
                raise JudgeInputRejected("Prepared Judge input requires a reviewed ASI01 text contract.")
            if not isinstance(prepared_prompt, str) or not prepared_prompt.strip():
                raise JudgeInputRejected("Reviewed Judge input is missing or blank.")
            if len(prepared_prompt) > 65536:
                raise JudgeInputRejected("Prepared Judge input exceeds the 65536-character limit; no truncation was performed.")
            if sha256(prepared_prompt.encode("utf-8")).hexdigest() != reviewed_input_sha256:
                raise JudgeInputRejected("Prepared Judge input differs from the reviewed disclosure binding.")
            if (any(value and value in prepared_prompt for value in sensitive_values)
                    or re.search(r"(?i)(?:\b(?:authorization|proxy-authorization|api[_-]?key|"
                                 r"access[_-]?token|password|secret)\s*[:=]|\bBearer\s+\S+|"
                                 r"-----BEGIN [A-Z ]*PRIVATE KEY-----)", prepared_prompt)):
                raise JudgeInputRejected("Prepared Judge input contains potentially sensitive data; disclosure blocked.")
            input_fields["untrusted_input"] = prepared_prompt

        evidence = []
        for item in observation.evidence:
            # Evidence identity is adapter/observer supplied. Do not forward tool
            # arguments, results, private headers, or arbitrary event data.
            data = public_evidence_data(item)
            evidence.append({
                "kind": item.kind, "source": item.source, "name": item.name,
                "success": item.success, "data": data, "reference": item.reference,
            })

        metadata = {}
        if type(observation.metadata.get("execution_success")) is bool:
            metadata["execution_success"] = observation.metadata["execution_success"]
        if type(observation.metadata.get("response_complete")) is bool:
            metadata["response_complete"] = observation.metadata["response_complete"]
        # Trace completeness stays on its scoped normalized evidence event;
        # a top-level metadata flag could imply broader coverage than observed.

        request = EvaluationRequest(
            schema_version="1.0", request_id=f"{testcase.id}-{uuid4().hex}",
            evaluation_type=semantic.skill,
            testcase={"id": testcase.id, "security_objective": testcase.objective,
                      **({"untrusted_input": testcase.variables["untrusted_source_prompt"]}
                         if testcase.category in {"identity_privilege_abuse", "unexpected_code_execution"}
                         and isinstance(testcase.variables.get("untrusted_source_prompt"), str) else {}),
                      **input_fields},
            trusted_context=context,
            observation={"response_text": observation.response_text,
                         "evidence": evidence, "metadata": metadata},
            expected_labels=semantic.expected_labels.copy(),
            skill=self._bundle_loader.load(semantic.skill).identity,
        )
        # All ASI routes must reject configured credential echoes before an
        # external provider call; later native-report redaction is insufficient.
        encoded = request.model_dump_json()
        if any(value and json.dumps(value, ensure_ascii=False)[1:-1] in encoded
               for value in sensitive_values):
            raise JudgeInputRejected("Judge request contains configured sensitive data; disclosure blocked.")
        return request
