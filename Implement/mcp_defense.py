from Command_guard.guard.auth.token_lifetime import TokenService
from typing import Any, Mapping
from Command_guard.hackurity_adapter import HackurityCommandGuard
from defenses.policy_engine import val_tool_name
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
IMPLEMENT_DIR = Path(__file__).resolve().parent

for directory in (PROJECT_ROOT, IMPLEMENT_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))
from Implement.rules import SecurityConfig, TrustedConfirmation
from Implement.test import security_proxy
from Implement.tool_registry import TOOL_HANDLERS
from defenses.input_validator import val_tool_arg
import copy
import json

from Command_guard.guard.hooks import (
    ALLOW,
    ASK,
    BLOCK,
    SANITIZE,
    Context,
    Decision,
)

from Command_guard.guard.policy_loader import load_policy
from Command_guard.guard.runtime import GuardRuntime


# ============================================================
# 3. RUNTIME SECURITY GATEWAY
# ============================================================
GUARD_DIR = PROJECT_ROOT / "Command_guard"
TOKEN_SERVICE = TokenService.from_env()
GUARD_POLICY_PATH = GUARD_DIR / "policy" / "policy.yaml"

COMMAND_GUARD = GuardRuntime(
    policy=load_policy(GUARD_POLICY_PATH),
    audit_path=PROJECT_ROOT / "logs" / "guard-audit.jsonl",
    token_service=TOKEN_SERVICE,
)

def execute_tool_call(
    *,
    tool_name: str,
    arguments: Mapping[str, Any],
    config: SecurityConfig,
    authenticated_user_id: str | None,
    access_token: str | None = None,
    token_service: TokenService | None = None,
    authorized_user_ids: frozenset[str],
    resource_is_authorized: bool,
    confirmation: TrustedConfirmation | None = None,
    source: str = "user_supplied_data",
    requested_policy_change: bool = False,
    change_from_trusted_admin: bool = False,
) -> dict[str, Any]:

    # Stage 0: Check registration and policy allowlist.
    try:
        val_tool_name(
            tool_name=tool_name,
            registered_tools=TOOL_HANDLERS,
            allowed_tools=config.allowed_tools,
        )
    except (ValueError, TypeError, PermissionError) as exc:
        return {
            "ok": False,
            "blocked": True,
            "reason": str(exc),
            "output": None,
        }
    
    # Stage 0.5: Command Guard inspection.
    try:
        guarded_arguments = dict(arguments)

        
        
        guard = HackurityCommandGuard(
            policy_path=GUARD_POLICY_PATH,
            audit_path=PROJECT_ROOT / "logs" / "guard-audit.jsonl",
            token_service=token_service or TOKEN_SERVICE,
            allowed_roots=[config.allowed_root],
        )
        
        decision, guarded_arguments, guard_ctx = guard.check_request(
            tool_name=tool_name,
            arguments=arguments,
            principal=authenticated_user_id,
            access_token=access_token,  
            server_name="filesystem",
        )

        if decision.action not in (ALLOW, SANITIZE):
            return {
                "ok": False,
                "blocked": True,
                "reason": decision.reason or "Command Guard denied the request.",
                "output": None,
            }

        if not isinstance(guarded_arguments, dict):
            return {
                "ok": False,
                "blocked": True,
                "reason": "Command Guard did not provide valid arguments.",
                "output": None,
            }

    except Exception:
        return {
            "ok": False,
            "blocked": True,
            "reason": "Command Guard failed; request blocked.",
            "output": None,
        }
    # Stage 1: Validate the request BEFORE execution.


    result = security_proxy(
        tool_name=tool_name,
        arguments=guarded_arguments,
        config=config,
        authenticated_user_id=authenticated_user_id,
        authorized_user_ids=authorized_user_ids,
        resource_is_authorized=resource_is_authorized,
        confirmation=confirmation,
        source=source,
        requested_policy_change=requested_policy_change,
        change_from_trusted_admin=change_from_trusted_admin,
    )

    # Stage 2: Reject any denied request.
    if not result["allowed"]:
        return {
            "ok": False,
            "blocked": True,
            "reason": result["reason"],
            "output": None,
        }

    # Stage 3: Find the actual implementation.
    handler = TOOL_HANDLERS.get(tool_name)

    # Fail closed if no implementation is registered.
    if handler is None:
        return {
            "ok": False,
            "blocked": True,
            "reason": "No registered handler for this tool.",
            "output": None,
        }

    # Stage 4: Execute only after authorization succeeds.
    

    try:
        output = handler(result["target"], guarded_arguments)

    except (OSError, ValueError):
        return {
            "ok": False,
            "blocked": False,
            "reason": "Tool execution failed.",
            "output": None,
        }

    # Stage 5: Inspect output before returning it.
    try:
        output_decision = guard.inspect_output(output, guard_ctx)

        if output_decision.action != ALLOW:
            return {
                "ok": False,
                "blocked": True,
                "reason": (
                    output_decision.reason
                    or "Command Guard blocked the tool output."
                ),
                "output": None,
            }

    except Exception:
        return {
            "ok": False,
            "blocked": True,
            "reason": "Output inspection failed; output withheld.",
            "output": None,
        }

    return {
        "ok": True,
        "blocked": False,
        "reason": "Authorized tool executed and output inspected successfully.",
        "output": output,
    }



# ============================================================
# 4. SAFE DEMONSTRATION
# ============================================================

if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder).resolve()

        # Create a sample file inside the permitted directory.
        (root / "notes.txt").write_text(
            "Hackurity runtime test.",
            encoding="utf-8",
        )

        config = SecurityConfig(allowed_root=root)

        result = execute_tool_call(
            tool_name="read_file",
            arguments={"path": "notes.txt"},
            config=config,
            authenticated_user_id="user_1",
            authorized_user_ids=frozenset({"user_1"}),
            resource_is_authorized=True,
        )

        print(result)
