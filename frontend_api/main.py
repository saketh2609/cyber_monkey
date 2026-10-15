from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEMO_ROOT = (PROJECT_ROOT / "demo_workspace").resolve()
DEMO_ROOT.mkdir(parents=True, exist_ok=True)
(DEMO_ROOT / "notes.txt").write_text(
    "Hackurity local demo note. This file is intentionally non-sensitive.\n",
    encoding="utf-8",
)

app = FastAPI(
    title="Hackurity Security Test API",
    description=(
        "Local demo API. Filesystem tool calls are routed through the existing "
        "Hackurity execute_tool_call gateway. This is not production authentication."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

class ToolCallRequest(BaseModel):
    tool_name: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)

class PromptRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=12000)

@app.get("/api/health")
def health():
    return {
        "ok": True,
        "service": "Hackurity Security Test API",
        "gateway_module_exists": (PROJECT_ROOT / "Implement" / "mcp_defense.py").is_file(),
        "demo_root_exists": DEMO_ROOT.is_dir(),
        "mode": "local-demo",
    }

@app.get("/api/config")
def config_info():
    return {
        "ok": True,
        "categories": [
            "prompt injection", "path traversal", "sensitive files",
            "authorization", "destructive operations", "tool allowlisting",
            "argument validation", "output inspection",
        ],
        "note": "Prompt/output fixture screening in the frontend is heuristic; gateway tool tests call the existing Python gateway.",
    }

@app.post("/api/tool-calls")
def tool_call(request: ToolCallRequest):
    # The browser must not decide its own identity, authorization set,
    # allowed root, or trusted confirmation. These are server-side demo values.
    # Modifying/destructive operations are disabled until a real trusted
    # confirmation flow is implemented server-side.
    if request.tool_name in {"write_file", "delete_file", "move_file"}:
        return {
            "ok": False,
            "blocked": True,
            "reason": "Modifying operations are disabled in this local demo.",
            "output": None,
        }

    try:
        from Implement.mcp_defense import execute_tool_call
        from Implement.rules import SecurityConfig
    except Exception:
        return {
            "ok": False,
            "blocked": True,
            "reason": (
                "Could not import the existing gateway or SecurityConfig. "
                "Check project module paths and the MCP_GUARD_SIGNING_KEY."
            ),
            "output": None,
        }

    # Demo identity only. Replace with authenticated server-side identity
    # before any non-local deployment.
    user_id = os.environ.get("HACKURITY_DEMO_USER_ID", "user_1")
    authorized_users = frozenset({user_id})
    config = SecurityConfig(allowed_root=DEMO_ROOT)

    try:
        result = execute_tool_call(
            tool_name=request.tool_name,
            arguments=request.arguments,
            config=config,
            authenticated_user_id=user_id,
            authorized_user_ids=authorized_users,
            resource_is_authorized=True,
            source="user_supplied_data",
        )
        return result
    except Exception:
        return {
            "ok": False,
            "blocked": True,
            "reason": "Gateway integration failed; request blocked.",
            "output": None,
        }

@app.post("/api/prompt-screen")
def prompt_screen(request: PromptRequest):
    # Transparent baseline helper only, not an LLM, policy engine, or proof
    # that the prompt is safe. The frontend labels this as heuristic.
    text = request.prompt.lower()
    indicators = [
        "ignore all previous instructions",
        "reveal the system prompt",
        "reveal hidden instructions",
        "disable all security checks",
        "send credentials",
        "exfiltrate",
        "bypass access control",
        "unrestricted mode",
    ]
    matches = [item for item in indicators if item in text]
    return {
        "ok": True,
        "flagged": bool(matches),
        "matches": matches,
        "mode": "heuristic",
        "note": "Heuristic screening only; this is not a definitive safety verdict.",
    }
