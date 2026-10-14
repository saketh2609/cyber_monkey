"""High-level runtime wrapper for the Track B command/path guard."""

from __future__ import annotations

import sys
from pathlib import Path

COMMAND_GUARD_ROOT = Path(__file__).resolve().parents[1]
if str(COMMAND_GUARD_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMAND_GUARD_ROOT))

import hashlib
import json
import re
import time
from typing import Any

from guard.auth.token_lifetime import TokenService, authenticate
from guard.checks.command import command_hook
from guard.checks.path import path_hook
from guard.hooks import Context, Decision, HookChain
 

_SECRET_PATTERNS = (
    re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*[^\s,;]{6,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)
_PROMPT_INJECTION_PATTERNS = (
    re.compile(r"(?i)ignore (all )?(previous|prior|above) instructions"),
    re.compile(r"(?i)reveal (the )?(system prompt|secrets|credentials)"),
    re.compile(r"(?i)you are now (?:the )?system"),
    re.compile(r"(?i)disregard (all )?(safety|security|previous instructions)"),
)
_SENSITIVE_KEYS = {"password", "secret", "token", "api_key", "apikey", "authorization", "credential"}


def _redact(value: Any, key: str = "") -> Any:
    """Bound and redact audit values so logs don't become a secret dump."""
    if key.lower() in _SENSITIVE_KEYS or any(word in key.lower() for word in ("password", "secret", "token", "credential", "api_key")):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in list(value.items())[:100]}
    if isinstance(value, (list, tuple)):
        return [_redact(v, key) for v in list(value)[:100]]
    if isinstance(value, str):
        return value[:500] + ("…[truncated]" if len(value) > 500 else "")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return f"[UNLOGGABLE:{type(value).__name__}]"


class GuardRuntime:
    """Policy, identity, command/path checks, output inspection and JSONL audit."""

    
    def _authenticate_token(
        self, msg: dict[str, Any], ctx: Context
    ) -> Decision:
        if self.token_service is None:
            return Decision.block(
                "TOK-001",
                "Token service is not configured",
            )

        claims, error = authenticate(self.token_service, ctx)

        if error is not None:
            return error

        if claims.aud != ctx.server_name:
            return Decision.block(
                "TOK-008",
                "Token audience does not match this server",
            )

        ctx.state["principal"] = claims.sub
        ctx.state["scopes"] = list(claims.scopes)

        return Decision.allow()

    def __init__(
        self,
        policy: dict[str, Any],
        audit_path: str | Path = "logs/guard-audit.jsonl",
        token_service: TokenService | None = None,
    ) -> None:
            self.policy = policy
            self.audit_path = Path(audit_path)
            self.token_service = token_service

            hooks = []

            if token_service is None:
                raise ValueError("TokenService is required for secure operation")

            hooks.append(self._authenticate_token)

            hooks.extend([
                self._authorize,
                path_hook,
                command_hook,
            ])

            self.chain = HookChain(hooks, timeout_s=2.0)


    def _server_policy(self, ctx: Context) -> dict[str, Any]:
        return ((self.policy.get("servers") or {}).get(ctx.server_name) or {})

    def _authorize(self, msg: dict[str, Any], ctx: Context) -> Decision:
        if msg.get("method") != "tools/call":
            return Decision.allow()
        params = msg.get("params")
        if not isinstance(params, dict):
            return Decision.block("AUTH-001", "Malformed tools/call params")
        tool = params.get("name")
        if not isinstance(tool, str) or not tool.strip():
            return Decision.block("AUTH-001", "Missing or invalid tool name")
        args = params.get("arguments", {})
        if not isinstance(args, dict):
            return Decision.block("INPUT-001", "Tool arguments must be a JSON object")

        server = self._server_policy(ctx)
        allowed_tools = server.get("allowed_tools")
        if not isinstance(allowed_tools, list) or tool not in allowed_tools:
            return Decision.block("AUTH-002", f"Tool {tool!r} is not explicitly allowed for server {ctx.server_name!r}")

        principal = ctx.state.get("principal")
        if not isinstance(principal, str) or not principal.strip():
            return Decision.block("AUTH-003", "Authenticated principal is missing")
        principals = server.get("allowed_principals")
        if isinstance(principals, list) and principal not in principals:
            return Decision.block("AUTH-004", "Principal is not authorized for this server")

        tool_roles = (server.get("tool_roles") or {}).get(tool)
        roles = ctx.state.get("roles", [])
        if tool_roles and not (isinstance(roles, list) and set(roles).intersection(tool_roles)):
            return Decision.block("AUTH-005", "Principal lacks a required role for this tool")
        return Decision.allow()

    async def check_request(self, message: dict[str, Any], ctx: Context) -> Decision:
        """Evaluate an incoming JSON-RPC request before forwarding it to an MCP server."""
        ctx.state["policy"] = self.policy
        decision = await self.chain.run(message, ctx)
        try:
            self._audit("request", message, ctx, decision)
        except RuntimeError:
            return Decision.block("AUDIT-001", "Audit log unavailable; request blocked")
        return decision

    def inspect_response(self, message: dict[str, Any], ctx: Context) -> Decision:
        """Inspect a JSON-RPC response before the agent receives it.

        Secret-shaped content is BLOCKED. Prompt-injection-looking content is ASKed for
        review; this is a heuristic, not a semantic guarantee.
        """
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            decision = Decision.block("OUTPUT-001", "Malformed JSON-RPC response")
            try:
                self._audit("response", message, ctx, decision)
            except RuntimeError:
                return Decision.block("AUDIT-001", "Audit log unavailable; response blocked")
            return decision
        text_chunks: list[str] = []

        def walk(value: Any, depth: int = 0) -> None:
            if depth > 12 or len(text_chunks) >= 500:
                return
            if isinstance(value, str):
                text_chunks.append(value[:20_000])
            elif isinstance(value, dict):
                for child in value.values():
                    walk(child, depth + 1)
            elif isinstance(value, list):
                for child in value[:200]:
                    walk(child, depth + 1)

        walk(message.get("result", message.get("error", {})))
        combined = "\n".join(text_chunks)
        for pattern in _SECRET_PATTERNS:
            if pattern.search(combined):
                decision = Decision.block("OUTPUT-002", "Response appears to contain a secret or credential")
                try:
                    self._audit("response", message, ctx, decision)
                except RuntimeError:
                    return Decision.block("AUDIT-001", "Audit log unavailable; response blocked")
                return decision
        for pattern in _PROMPT_INJECTION_PATTERNS:
            if pattern.search(combined):
                decision = Decision.ask("OUTPUT-003", "Response contains instruction-like text; review before passing it to the agent")
                try:
                    self._audit("response", message, ctx, decision)
                except RuntimeError:
                    return Decision.block("AUDIT-001", "Audit log unavailable; response blocked")
                return decision
        decision = Decision.allow()
        try:
            self._audit("response", message, ctx, decision)
        except RuntimeError:
            return Decision.block("AUDIT-001", "Audit log unavailable; response blocked")
        return decision

    def _audit(self, stage: str, message: Any, ctx: Context, decision: Decision) -> None:
        params = message.get("params", {}) if isinstance(message, dict) else {}
        record = {
            "timestamp_unix": time.time(),
            "stage": stage,
            "session_id": ctx.session_id,
            "server": ctx.server_name,
            "principal": ctx.state.get("principal"),
            "tool": params.get("name") if isinstance(params, dict) else None,
            "request_id": message.get("id") if isinstance(message, dict) else None,
            "arguments": _redact(params.get("arguments", {})) if isinstance(params, dict) else None,
            "decision": decision.action,
            "rule_id": decision.rule_id,
            "reason": decision.reason[:500],
            "severity": decision.severity,
            "message_sha256": hashlib.sha256(
                json.dumps(message, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest() if isinstance(message, (dict, list)) else None,
        }
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except OSError:
            # Audit failure must not silently allow a request; raise so the caller can fail closed.
            raise RuntimeError("Guard audit log could not be written")
