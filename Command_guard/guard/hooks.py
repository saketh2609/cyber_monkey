"""Hook / Decision interface, version 1.

FROZEN CONTRACT: Tracks B, C and D code against this file.
Change it only when all four track owners agree.

A hook is a function (message: dict, ctx: Context) -> Decision.
  * on_request(msg, ctx)  runs on messages going agent -> server
  * on_response(msg, ctx) runs on messages going server -> agent
A hook gets a COPY of the message. To change a message, return
Decision.sanitize(new_message, ...). Editing the copy does nothing.
"""
from __future__ import annotations

import asyncio
import copy
import inspect
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Union

INTERFACE_VERSION = 1

ALLOW, SANITIZE, ASK, BLOCK = "allow", "sanitize", "ask", "block"
ACTIONS = frozenset({ALLOW, SANITIZE, ASK, BLOCK})


@dataclass(frozen=True)
class Decision:
    action: str
    reason: str = ""
    rule_id: str = ""
    severity: str = "info"  # info | low | medium | high
    modified_message: dict[str, Any] | None = None

    @classmethod
    def allow(cls) -> "Decision":
        return cls(ALLOW, "ok")

    @classmethod
    def block(cls, rule_id: str, reason: str, severity: str = "high") -> "Decision":
        return cls(BLOCK, reason, rule_id, severity)

    @classmethod
    def ask(cls, rule_id: str, reason: str, severity: str = "medium") -> "Decision":
        return cls(ASK, reason, rule_id, severity)

    @classmethod
    def sanitize(cls, modified_message: dict[str, Any], rule_id: str,
                 reason: str, severity: str = "low") -> "Decision":
        return cls(SANITIZE, reason, rule_id, severity, modified_message)


@dataclass
class PendingRequest:
    id: Any
    method: str
    tool: str | None
    started: float  # time.monotonic()


@dataclass
class Context:
    session_id: str
    server_name: str
    # request id -> PendingRequest (shared by every call in this session)
    pending: dict[Any, PendingRequest] = field(default_factory=dict)
    # free per-session scratch space: trust level, taint flag, approved pins...
    state: dict[str, Any] = field(default_factory=dict)
    # set only for response hooks: the request this response answers
    request: PendingRequest | None = None


Hook = Callable[[dict, Context], Union[Decision, Awaitable[Decision]]]


def _modified_is_valid(orig: dict, mod: Any) -> bool:
    """A hook may change content, never identity or routing."""
    return (
        isinstance(mod, dict)
        and mod.get("jsonrpc") == "2.0"
        and ("id" in mod) == ("id" in orig)
        and mod.get("id") == orig.get("id")
        and mod.get("method") == orig.get("method")
    )


class HookChain:
    """Runs hooks in order. Anything odd becomes BLOCK (fail closed)."""

    def __init__(self, hooks=(), timeout_s: float = 2.0) -> None:
        self.hooks = list(hooks)
        self.timeout_s = timeout_s

    async def _call(self, hook: Hook, msg: dict, ctx: Context) -> Decision:
        name = getattr(hook, "__qualname__", repr(hook))
        arg = copy.deepcopy(msg)
        try:
            if inspect.iscoroutinefunction(hook):
                result = await asyncio.wait_for(hook(arg, ctx), self.timeout_s)
            else:
                loop = asyncio.get_running_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, hook, arg, ctx), self.timeout_s
                )
        except asyncio.TimeoutError:
            return Decision.block("GUARD-TIMEOUT", f"hook {name} timed out")
        except Exception as e:  # a buggy plugin must never crash or open the proxy
            return Decision.block("GUARD-HOOK-ERROR", f"hook {name} raised {type(e).__name__}")
        if not isinstance(result, Decision) or result.action not in ACTIONS:
            return Decision.block("GUARD-BAD-DECISION", f"hook {name} returned an invalid decision")
        return result

    async def run(self, msg: dict, ctx: Context) -> Decision:
        current = msg
        reasons: list[str] = []
        rules: list[str] = []
        changed = False
        for hook in self.hooks:
            d = await self._call(hook, current, ctx)
            if d.action in (BLOCK, ASK):
                return d  # short-circuit
            if d.action == SANITIZE:
                if not _modified_is_valid(msg, d.modified_message):
                    return Decision.block("GUARD-BAD-SANITIZE",
                                          "hook changed id/method or returned bad JSON-RPC")
                current = d.modified_message
                changed = True
                reasons.append(d.reason)
                rules.append(d.rule_id)
        if changed:
            return Decision(SANITIZE, "; ".join(reasons), ",".join(rules), "low", current)
        return Decision.allow()
