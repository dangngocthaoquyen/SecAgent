"""Bounded repository discovery and non-executable compatibility drafts."""
from pathlib import Path
import re
import stat
from typing import Literal
from pydantic import Field, model_validator
import yaml
from testing.testcase_loader import TestCaseLoader
from payloads.loader import PayloadLoader
from attack_modules.registry import build_default_attack_module_registry
from integrations.external_evaluator.skills import SkillBundleLoader
from reporting.redaction import Redactor

def redact_text(text):
    return Redactor().clean(re.sub(r"(?:[A-Za-z]:[\\/]|/)[^\s]+", "[LOCATION]", text))
from workflow.models import ClosedModel, TargetDraft, Identifier

ROOT = Path(__file__).resolve().parents[3]
ASI = {'goal_hijacking': ('ASI01', 'Agent Goal Hijacking'),
       'tool_misuse': ('ASI02', 'Tool Misuse & Exploitation'),
       'identity_privilege_abuse': ('ASI03', 'Identity & Privilege Abuse'),
       'unexpected_code_execution': ('ASI05', 'Unexpected Code Execution')}


class PlanSelection(ClosedModel):
    target: TargetDraft
    asi_categories: list[Literal['ASI01','ASI02','ASI03','ASI05']] = Field(min_length=1,max_length=4)
    testcase_ids: list[Identifier] = Field(default_factory=list,max_length=100)

    @model_validator(mode='after')
    def unique(self):
        if len(set(self.asi_categories)) != len(self.asi_categories) or len(set(self.testcase_ids)) != len(self.testcase_ids):
            raise ValueError('Duplicate selection')
        return self


def safe_file(path, root):
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Outside repository scope')
    for part in (path, *path.parents):
        if part == root.parent: break
        if part.is_symlink() or getattr(part.stat(), 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError('Linked artifact')
    if not path.is_file() or path.stat().st_size > 262144:
        raise ValueError('Invalid artifact')


class TestcaseCatalog:
    def __init__(self, root=ROOT):
        self.items = []
        self.paths = {}
        self.invalid_records = 0
        registry = build_default_attack_module_registry()
        for category, (asi, _) in ASI.items():
            paths = sorted((root/'testcases'/category).glob('*.yaml'))
            if len(paths)>100: raise ValueError('Too many testcases')
            for path in paths:
                try:
                    safe_file(path, root)
                    case = TestCaseLoader().load(path)
                    if case.category != category or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',case.id):
                        raise ValueError('Invalid identity')
                    claims = {r.id.split(":")[0] for r in case.taxonomy.owasp if r.id.startswith('ASI')}
                    if claims and claims != {asi}: raise ValueError('Contradictory taxonomy')
                    if any(i['id']==case.id for i in self.items): raise ValueError('Duplicate identity')
                    reasons = []
                    state = 'unknown'
                    try: registry.resolve(case.attack_module)
                    except ValueError: state='unsupported'; reasons.append('Attack module is not registered.')
                    try:
                        payload_path=root/'payload'/f'{category}.yaml'
                        safe_file(payload_path,root)
                        payloads=PayloadLoader().load_repository(payload_path)
                        if len(case.payload_refs)!=1 or any(ref not in payloads for ref in case.payload_refs):
                            raise ValueError('Payload references unavailable')
                    except (ValueError,OSError,yaml.YAMLError):
                        state='requires_configuration' if state!='unsupported' else state
                        reasons.append('Payload binding requires review.')
                    required=[]
                    if category=='identity_privilege_abuse':
                        required=['Verified A/B authorization baseline','Identity and privilege action observer']
                    elif category=='unexpected_code_execution':
                        required=['Verified isolated sandbox and exact canary allowlist','Execution action observer']
                    elif any(r.type=='collector_receipt' for r in case.evaluation.rules):
                        required=['Correlated independent collector receipt','Reviewed web-fetch boundary']
                    elif category=='tool_misuse':
                        required=['Reviewed tool mapping and tool-action evidence']
                    elif case.evaluation.semantic and case.evaluation.semantic.trusted_context.get('required_fetch_url'):
                        required=['Web-fetch capability and fetch evidence','Complete action scope']
                    if required:
                        if state!='unsupported': state='requires_configuration'
                        reasons.extend(required)
                    semantic=case.evaluation.semantic
                    if semantic and semantic.enabled:
                        try: SkillBundleLoader().load(semantic.skill)
                        except ValueError:
                            reasons.append('Required semantic skill is unavailable.')
                        reasons.append('Judge configuration and evidence contract require review; no Judge is enabled here.')
                        if state!='unsupported': state='requires_configuration'
                    reasons.append('Target capabilities are configured claims; per-testcase runtime compatibility is not verified.')
                    self.items.append(dict(id=case.id,name=redact_text(case.name)[:160],asi_category=asi,
                        description=redact_text(case.description or '')[:280],compatibility=state,
                        reason=reasons[0],requirements=reasons,required_capabilities=required,
                        taxonomy_basis='repository_category_mapping'))
                    self.paths[case.id] = path
                except (ValueError,OSError,yaml.YAMLError): self.invalid_records+=1
        self.items.sort(key=lambda i:i['id'])

    def preview(self, selection, catalog, *, plan=False):
        errors=catalog.validate(selection.target)
        if errors: raise ValueError('Target configuration is stale, unreviewed or invalid.')
        items=[dict(i) for i in self.items if i['asi_category'] in selection.asi_categories]
        if plan:
            if not selection.testcase_ids: raise ValueError('Select at least one testcase.')
            by_id={i['id']:i for i in items}
            if any(i not in by_id for i in selection.testcase_ids): raise ValueError('Unknown or out-of-scope testcase.')
            items=[by_id[i] for i in sorted(selection.testcase_ids)]
            if any(i['compatibility']=='unsupported' for i in items): raise ValueError('Unsupported testcase selected.')
        return dict(workflow_schema_version='1.0.0',target_id=selection.target.target_id,
            profile_revision=selection.target.profile_revision,asi_categories=sorted(selection.asi_categories),
            items=items,invalid_records=self.invalid_records,
            counts={'applicable':sum(i['compatibility']=='supported' for i in items),
                    'blocked':sum(i['compatibility'] in ('unsupported','requires_configuration') for i in items),
                    'unknown':sum(i['compatibility']=='unknown' for i in items)},
            connectivity='not_checked',probe='unsupported',execution_status='not_started',
            executable=False,readiness='Non-executable draft: execution authorization and required evidence are not established.')
