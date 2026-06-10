"""Nexus runtime charter."""

from charter.context import Charter, current_charter
from charter.contract import ExecutionContract, load_contract
from charter.degradation import degraded_marker, sanitize_scan_error
from charter.exceptions import (
    BudgetExhausted,
    CharterViolation,
    ContractInvalid,
    DirectInvocationBlocked,
    ToolForbidden,
    ToolNotPermitted,
)
from charter.tools import ToolRegistry
from charter.verifier import VerificationResult, verify_audit_log

__version__ = "0.1.0"

__all__ = [
    "BudgetExhausted",
    "Charter",
    "CharterViolation",
    "ContractInvalid",
    "DirectInvocationBlocked",
    "ExecutionContract",
    "ToolForbidden",
    "ToolNotPermitted",
    "ToolRegistry",
    "VerificationResult",
    "current_charter",
    "degraded_marker",
    "load_contract",
    "sanitize_scan_error",
    "verify_audit_log",
]
