from enum import Enum

from pydantic import BaseModel

class EvaluationStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"


class EvaluationResult(BaseModel):
    status: EvaluationStatus
    passed: bool
    reason: str
    evidence: str | None = None
