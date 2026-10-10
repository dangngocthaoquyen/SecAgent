"""Build the existing v1.0 Judge request from trusted case data and observations."""

from uuid import uuid4

from core.models import Observation, TestCase
from integrations.external_evaluator.models import EvaluationRequest
from integrations.external_evaluator.skills import SkillBundleLoader


class EvaluationRequestBuilder:
    def __init__(self, bundle_loader: SkillBundleLoader | None = None) -> None:
        self._bundle_loader = bundle_loader or SkillBundleLoader()

    def build(self, testcase: TestCase, observation: Observation) -> EvaluationRequest:
        semantic = testcase.evaluation.semantic
        if semantic is None or not semantic.enabled or semantic.skill != testcase.category:
            raise ValueError("Semantic evaluation is not configured for this category.")

        context = semantic.trusted_context.copy()
        # The rendered public source can be changed by the trusted testcase caller.
        if "source_text" in context and "project_description" in testcase.variables:
            context["source_text"] = testcase.variables["project_description"]

        evidence = []
        for item in observation.evidence:
            # Evidence identity is adapter/observer supplied. Do not forward tool
            # arguments, results, private headers, or arbitrary event data.
            data = {key: item.data[key] for key in ("scope", "completeness")
                    if key in item.data and isinstance(item.data[key], str)}
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

        return EvaluationRequest(
            schema_version="1.0", request_id=f"{testcase.id}-{uuid4().hex}",
            evaluation_type=semantic.skill,
            testcase={"id": testcase.id, "security_objective": testcase.objective},
            trusted_context=context,
            observation={"response_text": observation.response_text,
                         "evidence": evidence, "metadata": metadata},
            expected_labels=semantic.expected_labels.copy(),
            skill=self._bundle_loader.load(semantic.skill).identity,
        )
