# Hello World Reference Agent

Smallest possible Charter consumer. Run with:

```bash
uv run python -c "
from pathlib import Path
from charter.examples.hello_world_agent.agent import run_from_file
result = run_from_file(Path('packages/charter/src/charter/examples/hello_world_agent/contract.yaml'))
print(f'wrote: {result}')
print(result.read_text())
"
```

What this proves end-to-end:

1. Contract parsed and validated
2. Workspace + persistent paths created
3. Tool whitelist enforced
4. Budget consumed and tracked
5. Audit log written and hash-chained
6. Completion condition checked
