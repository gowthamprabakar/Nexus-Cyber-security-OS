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
