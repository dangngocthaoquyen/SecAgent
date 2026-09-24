"""Network-free integration coverage for direct MCP tool misuse."""

from pathlib import Path
from typing import Any

from core.models import EvaluationStatus
from core.models import TestInput as CoreTestInput
from payloads import PayloadLoader, PayloadRenderer
from targets import load_target
from targets.adapters import McpJsonRpcTargetAdapter
from testing import Executor, Runner, TestCaseLoader
from tools.http import HttpResponse


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class FakeMcpHttpClient:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def request(self, **kwargs: Any) -> HttpResponse:
        self.requests.append(kwargs)
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            '{"success":true,"output":"Executed: echo '
                            'SECAGENT_TOOLBOT_TM002",'
                            '"note":"Command logged to sandbox"}'
                        ),
                    }
                ]
            },
        }
        return HttpResponse(
            status_code=200,
            headers={"content-type": "application/json"},
            text="json-rpc response",
            json_body=body,
            duration_ms=1.0,
        )


def test_tm002_pipeline_normalizes_real_contract_and_fails_tool_rule() -> None:
    testcase = TestCaseLoader().load(
        REPOSITORY_ROOT / "testcases" / "tool_misuse" / "TM-002.yaml"
    )
    target = load_target(
        REPOSITORY_ROOT / "configs" / "targets" / "dvaa-toolbot.yaml"
    )
    payloads = PayloadLoader().load_repository(
        REPOSITORY_ROOT / "payload" / "tool_misuse.yaml"
    )
    command = PayloadRenderer().render(
        payloads[testcase.payload_refs[0]], testcase.variables
    )
    test_input = CoreTestInput(
        id="tm002-input",
        payload_ref=testcase.payload_refs[0],
        parameters={
            "tool_call": {
                "name": testcase.variables["tool_name"],
                "arguments": {"command": command},
            }
        },
    )
    client = FakeMcpHttpClient()

    result = Runner(
        executor=Executor(
            adapters={
                "generic_mcp_jsonrpc": McpJsonRpcTargetAdapter(client)
            }
        )
    ).run(testcase, target, test_input)

    assert result.status is EvaluationStatus.FAIL
    assert result.matched_rule_id == "direct-sensitive-tool-executed"
    assert client.requests[0]["json_body"]["params"] == {
        "name": "execute",
        "arguments": {"command": "echo SECAGENT_TOOLBOT_TM002"},
    }
