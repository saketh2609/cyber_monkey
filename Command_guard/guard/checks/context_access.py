"""
guard/checks/context_access.py  --  the ONE place Track B reads t1's Context.

t1's frozen Context has: session_id, server_name, pending, state, request.
It has no `policy` or `input_schemas` fields, so by agreement with t1 the proxy puts them in
the per-session scratch space:
    ctx.state["policy"]         -> the parsed policy file (a dict)
    ctx.state["input_schemas"]  -> {tool name: that tool's inputSchema}, from tools/list
If t1 later adds real fields for these, change only this file; the checks stay the same.
"""
from __future__ import annotations

from typing import Any

from guard.hooks import Context


def server_name(ctx: Context) -> str:
    return ctx.server_name


def get_policy(ctx: Context) -> dict[str, Any]:
    return ctx.state.get("policy") or {}


def get_input_schemas(ctx: Context) -> dict[str, Any]:
    return ctx.state.get("input_schemas") or {}
