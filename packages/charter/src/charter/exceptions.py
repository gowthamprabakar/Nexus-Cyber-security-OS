"""Charter exception hierarchy."""


class CharterViolation(Exception):
    """Base for any violation of the runtime charter."""


class ContractInvalid(CharterViolation):
    """Execution contract failed validation."""

    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"contract invalid at '{field}': {reason}")


class BudgetExhausted(CharterViolation):
    """Agent exceeded its budget envelope."""

    def __init__(self, dimension: str, limit: int | float, used: int | float) -> None:
        self.dimension = dimension
        self.limit = limit
        self.used = used
        super().__init__(f"budget '{dimension}' exhausted: used {used} of limit {limit}")


class ToolNotPermitted(CharterViolation):
    """Agent attempted to call a tool not in its permitted list."""

    def __init__(self, tool: str, permitted: list[str]) -> None:
        self.tool = tool
        self.permitted = permitted
        super().__init__(f"tool '{tool}' not permitted (allowed: {permitted})")


class ToolForbidden(CharterViolation):
    """Agent attempted to call a tool named in its ``forbidden_tools`` list.

    Defense-in-depth only: the contract validator already guarantees
    ``forbidden_tools`` and ``permitted_tools`` do not overlap, so a forbidden
    tool would also fail the permitted check. This distinct error makes an
    explicit-denial hit legible in the audit trail (see ADR-016 Mechanism 3).
    """

    def __init__(self, tool: str, forbidden: list[str]) -> None:
        self.tool = tool
        self.forbidden = forbidden
        super().__init__(f"tool '{tool}' is explicitly forbidden (denied: {forbidden})")


class DirectInvocationBlocked(CharterViolation):
    """A registered tool was invoked outside of a charter-mediated dispatch.

    Registered tools are reachable only through ``Charter.call_tool()`` /
    ``ToolRegistry.call()`` so that the permitted-tools whitelist, budget meter,
    and audit log gate every call. Calling the registry-held callable directly
    bypasses that gate and is blocked (see ADR-016 Mechanism 1).
    """

    def __init__(self, tool: str) -> None:
        self.tool = tool
        super().__init__(
            f"tool '{tool}' was invoked directly; registered tools must be called "
            f"via ctx.call_tool(...) so the charter can gate, budget, and audit them"
        )
