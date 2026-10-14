
from pathlib import Path
from typing import Any, Mapping
import asyncio
from Command_guard.guard.auth.token_lifetime import TokenService
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


class HackurityCommandGuard:
    """Adapter between Hackurity tool calls and Command Guard."""

    
    def __init__(
        self,
        policy_path: str | Path,
        audit_path: str | Path = "logs/guard-audit.jsonl",
        token_service: TokenService | None = None,
        allowed_roots: list[str | Path] | None = None,
    ) -> None:
        if token_service is None:
            raise ValueError("TokenService is required for secure operation")

        self.policy = load_policy(policy_path)

        # Optional explicit root override for isolated tests and sandbox demos.
        if allowed_roots is not None:
            servers = self.policy.setdefault("servers", {})
            filesystem = servers.setdefault("filesystem", {})
            filesystem["allowed_roots"] = [
                str(Path(root).resolve()) for root in allowed_roots
            ]

        self.runtime = GuardRuntime(
            self.policy,
            audit_path,
            token_service=token_service,
        )
        self.token_service = token_service

    def check_request(
        self,
        *,
        tool_name: str,
        arguments: Mapping[str, Any],
        principal: str | None,
        server_name: str = "filesystem",
        access_token: str | None = None,
        roles: list[str] | None = None,
        session_id: str = "hackurity-local",
    ) -> tuple[Decision, dict[str, Any] | None, Context]:
        
        ctx = Context(
            session_id=session_id,
            server_name=server_name,
            state={
                "principal": principal,
                "roles": roles or [],
                "auth_token": access_token,
            },
        )
        
        message = {
            "jsonrpc": "2.0",
            "id": "hackurity-tool-call",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": dict(arguments),
            },
        }

        try:
            decision = asyncio.run(
                self.runtime.check_request(message, ctx)
            )
        except RuntimeError:
            decision = Decision.block(
                "GUARD-RUNTIME-001",
                "Command Guard could not safely evaluate the request.",
            )

        if decision.action == ALLOW:
            return decision, dict(arguments), ctx

        if decision.action == SANITIZE:
            modified = decision.modified_message
            params = modified.get("params") if isinstance(modified, dict) else None

            if (
                not isinstance(params, dict)
                or params.get("name") != tool_name
                or not isinstance(params.get("arguments"), dict)
            ):
                return (
                    Decision.block(
                        "GUARD-SANITIZE-001",
                        "Invalid sanitized tool request.",
                    ),
                    None,
                    ctx,
                )

            return decision, params["arguments"], ctx

        # ASK is not approval. BLOCK and ASK both stop execution.
        return decision, None, ctx

    def inspect_output(self, output: Any, ctx: Context) -> Decision:
        response = {
            "jsonrpc": "2.0",
            "id": "hackurity-tool-call",
            "result": {
                "content": [
                    {"type": "text", "text": str(output)}
                ]
            },
        }

        try:
            return self.runtime.inspect_response(response, ctx)
        except Exception:
            return Decision.block(
                "GUARD-OUTPUT-001",
                "Command Guard could not inspect the tool output.",
            )
