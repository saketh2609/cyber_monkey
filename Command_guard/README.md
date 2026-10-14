# Command Guard — Track B (revised prototype)

A Python security-checking layer for the AI-agent ↔ MCP-tool trust boundary. It evaluates JSON-RPC `tools/call` requests before they are forwarded. It does **not** execute operating-system commands and does **not** yet implement an MCP transport/proxy.

## What is included

- `guard/checks/command.py`: command/argument allowlist checks (CMD rules).
- `guard/checks/path.py`: path traversal, sensitive path, normalization and symlink-resolving path checks (PATH rules).
- `guard/hooks.py`: fail-closed async hook chain with ALLOW / ASK / BLOCK / SANITIZE contract.
- `guard/runtime.py`: integration wrapper adding deny-by-default tool allowlisting, authenticated-principal checks, optional role checks, response inspection, and JSONL audit events.
- `policy/policy.yaml`: example policy. **Replace sample principals and roots for your environment.**
- `tests/`: regression and runtime tests.

## Requirements

- Python 3.10+
- PyYAML for loading the sample YAML policy (`pip install pyyaml`)

## Run tests

From this directory:

```powershell
python -m unittest discover -v
```

## Use the runtime wrapper

```python
import asyncio
from pathlib import Path
from guard.hooks import Context
from guard.policy_loader import load_policy
from guard.runtime import GuardRuntime

policy = load_policy("policy/policy.yaml")
guard = GuardRuntime(policy, audit_path="logs/guard-audit.jsonl")
ctx = Context(
    session_id="demo-session",
    server_name="shell",
    state={"principal": "demo-user", "roles": ["operator"]},
)
request = {
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "run_command", "arguments": {"command": "ls -l"}},
}
decision = asyncio.run(guard.check_request(request, ctx))
print(decision.action, decision.rule_id, decision.reason)
# Forward to MCP server ONLY when decision.action == "allow".
```

Call `inspect_response(response, ctx)` before returning a tool result to the agent. A BLOCK or ASK must not be forwarded as ordinary trusted tool output; the host application must enforce that decision.

## Security boundaries / known limitations

- This code checks requests; it does not itself proxy network traffic. A caller can bypass it unless every protected MCP call is routed through the wrapper.
- The command check does not make arbitrary process execution safe. A production command tool should use a fixed executable allowlist, argument arrays (never `shell=True`), OS-level sandboxing, timeouts, and least privilege.
- Output secret/prompt-injection checks are heuristic. They cannot prove that output is safe or understand every indirect prompt injection.
- Audit logging stores redacted/truncated arguments and a message hash. Protect the log directory and rotate logs in production.
- Authentication values in `Context.state` must be set by trusted host code, never copied from tool arguments or model content.
- Run inside a sandbox with OS permissions and network controls for real deployments.
