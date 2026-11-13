"""Read-only admission decisions. No dispatch, target I/O, or reusable run token."""
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Literal
from pydantic import Field, AwareDatetime, model_validator
from testing.evaluation_config import RunnerEvaluationConfig
from core.models import TestInput
from testing.testcase_binding import bind_testcase_variables
from testing.testcase_loader import TestCaseLoader
from payloads import PayloadLoader, PayloadRenderer
from attack_modules.registry import build_default_attack_module_registry
from integrations.external_evaluator.skills import SkillBundleLoader
from workflow.models import ClosedModel, Identifier
from workflow.plans import PlanSelection, TestcaseCatalog, ROOT, safe_file


class ExecutionGrant(ClosedModel):
    authorization_id: Identifier | None = None
    target_id: Identifier
    profile_revision: str = Field(pattern=r'^[a-f0-9]{64}$')
    policy_ref: Identifier
    testcase_id: Identifier
    asset_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    scope: Literal['security_test_execution']
    expires_at: AwareDatetime = Field(strict=False)


class AdmissionPolicy(ClosedModel):
    revision: Identifier = 'deny-by-default'
    grants: list[ExecutionGrant] = Field(default_factory=list,max_length=20)
    max_testcases: int = Field(default=1,ge=1,le=1)
    max_target_requests: int = Field(default=1,ge=1,le=1)
    max_timeout_seconds: int = Field(default=30,ge=1,le=60)

    @model_validator(mode='after')
    def unique_authorizations(self):
        ids=[g.authorization_id for g in self.grants if g.authorization_id is not None]
        if len(ids)!=len(set(ids)):
            raise ValueError('Duplicate execution authorization identity.')
        return self


class AdmissionRequest(PlanSelection):
    target_request_budget: int = Field(default=1,ge=1,le=10)
    expected_plan_id: str | None = Field(default=None,pattern=r'^[a-f0-9]{64}$')
    evaluation_mode: Literal['rule_only','hybrid'] = 'rule_only'


def digest(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest()


class AdmissionService:
    def __init__(self, catalog, policy=None, *, root=ROOT, runtime_bindings=None,
                 hybrid_config: RunnerEvaluationConfig | None = None):
        self.catalog=catalog
        self.policy=policy or AdmissionPolicy()
        self.root=root
        # Trusted in-process adapter wiring only. Never populated from HTTP/JSON.
        # Production supplies none until a reviewed runtime integration exists.
        self.bindings=runtime_bindings or {}
        self.hybrid_config=hybrid_config

    def assess(self, request, *, admit=False):
        inventory=TestcaseCatalog(self.root)
        errors=list(self.catalog.validate(request.target))
        if request.evaluation_mode=='hybrid' and self.hybrid_config is None:
            errors.append('hybrid_judge_not_configured')
        if not request.testcase_ids: errors.append('no_testcases_selected')
        if len(request.testcase_ids)>self.policy.max_testcases: errors.append('testcase_budget_exceeded')
        if request.target_request_budget>self.policy.max_target_requests or request.target_request_budget<len(request.testcase_ids): errors.append('request_budget_exceeded')
        if request.target.timeout_seconds>self.policy.max_timeout_seconds: errors.append('timeout_budget_exceeded')
        rows=[]; assets={}; bound_hashes={}
        now=datetime.now(timezone.utc)
        for identity in sorted(request.testcase_ids):
            blockers=[]
            stages=dict(discovered=False,schema_valid=False,target_protocol_compatible=False,
                required_inputs_resolved=False,required_evidence_available=False,
                execution_authorized=False,runtime_preflight_satisfied=False)
            try:
                path=inventory.paths[identity]
                item=next(i for i in inventory.items if i['id']==identity)
                if item['asi_category'] not in request.asi_categories: raise ValueError('scope')
                safe_file(path,self.root)
                case=TestCaseLoader().load(path)
                if (request.evaluation_mode=='hybrid' and
                        (case.evaluation.semantic is None or not case.evaluation.semantic.enabled
                         or case.evaluation.semantic.skill!=case.category)):
                    blockers.append('verified_semantic_contract_missing')
                stages.update(discovered=True,schema_valid=True)
                payload_path=self.root/'payload'/f'{case.category}.yaml'
                safe_file(payload_path,self.root)
                bundle=None
                if case.evaluation.semantic and case.evaluation.semantic.enabled:
                    bundle=SkillBundleLoader().load(case.evaluation.semantic.skill)
                assets[identity]=digest([sha256(path.read_bytes()).hexdigest(),sha256(payload_path.read_bytes()).hexdigest(),
                                         sha256(bundle.system_prompt.encode()).hexdigest() if bundle else None])
                binding=self.bindings.get((request.target.target_id,request.target.profile_revision,identity,assets[identity]))
                if not binding: blockers.append('reviewed_runtime_binding_missing')
                binding=binding or {}
                stages['target_protocol_compatible']=binding.get('protocol')=='openai-chat'
                if not stages['target_protocol_compatible']: blockers.append('protocol_compatibility_not_established')
                grants=[g for g in self.policy.grants if g.target_id==request.target.target_id and g.profile_revision==request.target.profile_revision and g.policy_ref==request.target.policy_ref and g.testcase_id==identity and g.asset_sha256==assets[identity] and g.expires_at>now]
                stages['execution_authorized']=bool(grants)
                if not grants: blockers.append('execution_authorization_missing_or_expired')
                if case.category!='goal_hijacking': blockers.append('outside_first_asi01_slice')
                if case.category=='identity_privilege_abuse': blockers.append('authorization_baseline_missing')
                if case.category=='unexpected_code_execution': blockers.append('sandbox_configuration_missing')
                collector_required=any(r.type=='collector_receipt' for r in case.evaluation.rules)
                deferred_fixture=(identity=='GH-WEB-001' and collector_required
                    and binding.get('fresh_fixture_factory') is True
                    and binding.get('collector_recording_executor') is True)
                if collector_required and not deferred_fixture:
                    # Only a trusted in-process factory can defer fresh correlation
                    # until dispatch. Browser assertions and archived receipts cannot.
                    blockers.extend(['fresh_collector_binding_missing','collector_recording_executor_not_wired'])
                if case.evaluation.strategy=='semantic': blockers.append('semantic_evaluator_not_enabled')
                if not binding.get('response_observer'): blockers.append('response_observer_missing')
                if not binding.get('report_sink'): blockers.append('report_persistence_not_wired')
                try:
                    payloads=PayloadLoader().load_repository(payload_path)
                    if len(case.payload_refs)!=1: raise ValueError('binding')
                    payload=payloads[case.payload_refs[0]]
                    if payload.category!=case.category: raise ValueError('payload category')
                    if deferred_fixture:
                        # The factory creates and binds real values after an exclusive
                        # claim. Do not invent a preview run ID or collector receipt.
                        if (binding.get('variables') or binding.get('environment')
                                or not case.evaluation.semantic
                                or not case.evaluation.semantic.trusted_context.get('collector_verification_required')):
                            raise ValueError('invalid deferred fixture')
                        build_default_attack_module_registry().resolve(case.attack_module)
                        bound_hashes[identity]=digest([case.model_dump(),payload.id,binding])
                    else:
                        bound=bind_testcase_variables(case,binding.get('variables',{}))
                        prompt=PayloadRenderer().render(payload,bound.variables)
                        serialized=json.dumps(bound.model_dump(),default=str)+prompt
                        if '{{' in serialized or 'REQUIRES_' in serialized or '/unconfigured' in serialized: raise ValueError('unbound')
                        test_input=TestInput(id='admission-preview',prompt=prompt,payload_ref=payload.id,environment=binding.get('environment',{}))
                        build_default_attack_module_registry().resolve(bound.attack_module).prepare(bound,test_input)
                        bound_hashes[identity]=digest([bound.model_dump(),prompt,binding])
                    stages['required_inputs_resolved']=True
                except (ValueError,KeyError): blockers.append('required_inputs_or_preflight_unresolved')
                stages['required_evidence_available']=bool(binding.get('response_observer')) and not any('collector' in b or 'baseline' in b or 'sandbox' in b for b in blockers)
                stages['runtime_preflight_satisfied']=not blockers
            except (ValueError,KeyError,OSError): blockers.append('invalid_testcase_or_assets')
            rows.append(dict(testcase_id=identity,ready=not blockers and not errors,blockers=sorted(set(blockers)),stages=stages))
        # A plan describes stable execution settings. A newly issued grant is
        # checked independently and must not silently change that plan identity.
        stable_policy=self.policy.model_dump(exclude={'grants'})
        evaluation_revision=(digest(self.hybrid_config.model_dump(mode='json'))
                             if request.evaluation_mode=='hybrid' and self.hybrid_config else None)
        material=dict(selection=request.model_dump(exclude={'expected_plan_id'}),policy=stable_policy,assets=assets,
                      bindings=bound_hashes,evaluation_revision=evaluation_revision)
        plan_id=digest(material)
        if admit and request.expected_plan_id!=plan_id: errors.append('stale_or_missing_plan_identity')
        if errors:
            for row in rows:
                row['ready'] = False
        ready=sum(r['ready'] for r in rows) if not errors else 0
        admitted=admit and bool(rows) and ready==len(rows) and not errors
        return dict(workflow_schema_version='1.0.0',plan_id=plan_id,items=rows,asset_sha256=assets,
            ready_count=ready,blocked_count=len(rows)-ready,blockers=sorted(set(errors)),
            admitted=admitted,decision='admitted' if admitted else 'blocked' if ready!=len(rows) or errors or not rows else 'ready_for_admission',
            execution_status='not_started',dispatch_available=False,connectivity='not_checked',
            evaluation_mode=request.evaluation_mode,
            max_judge_calls=self.hybrid_config.max_judge_calls if request.evaluation_mode=='hybrid' and self.hybrid_config else 0,
            judge_configuration='configured_unverified' if self.hybrid_config else 'unavailable',
            execution_model='sequential',
            limitation='Decision only, not a reusable bearer token. Revalidate immediately before future dispatch.')
