"""Local FastAPI bridge for the existing Hackurity gateway.
This is a localhost development adapter, not a production auth boundary.
The browser cannot provide trusted confirmations; destructive tools are blocked.
Prompt tests are previews and do not invoke an LLM or execute tools.
"""
import os
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = PROJECT_ROOT / "demo_workspace"
ALLOWED_ROOT = Path(os.environ.get("HACKURITY_ALLOWED_ROOT", str(DEFAULT_ROOT))).resolve()
USER_ID = os.environ.get("HACKURITY_USER_ID", "user_1")
AUTHORIZED_IDS = frozenset(x.strip() for x in os.environ.get("HACKURITY_AUTHORIZED_USER_IDS", USER_ID).split(",") if x.strip())
app = FastAPI(title="Hackurity Local API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"], allow_credentials=False, allow_methods=["GET","POST"], allow_headers=["Content-Type"])

class ToolCallRequest(BaseModel):
    tool_name: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)
class PromptTestRequest(BaseModel):
    scenario: str = Field(min_length=1, max_length=40)
    prompt: str = Field(min_length=1, max_length=5000)

@app.on_event("startup")
def startup():
    ALLOWED_ROOT.mkdir(parents=True, exist_ok=True)
    note = ALLOWED_ROOT / "notes.txt"
    if not note.exists():
        note.write_text("Hackurity local demo workspace. No sensitive data.\\n", encoding="utf-8")

@app.get("/api/health")
def health():
    return {"ok": True, "mode": "local-api", "allowed_root_configured": str(ALLOWED_ROOT), "principal_configured": USER_ID, "recent_events": []}

@app.post("/api/tool-calls")
def tool_call(request: ToolCallRequest):
    if request.tool_name in {"write_file", "delete_file", "move_file"}:
        return {"ok": False, "blocked": True, "reason": "This UI bridge does not expose destructive tools until trusted server-side approval is implemented.", "output": None}
    try:
        from Implement.mcp_defense import execute_tool_call
        from Implement.rules import SecurityConfig
        config = SecurityConfig(allowed_root=ALLOWED_ROOT)
        return execute_tool_call(tool_name=request.tool_name, arguments=request.arguments, config=config, authenticated_user_id=USER_ID, authorized_user_ids=AUTHORIZED_IDS, resource_is_authorized=True, confirmation=None, source="user_supplied_data")
    except Exception as exc:
        return {"ok": False, "blocked": True, "reason": f"Gateway API could not safely process the request ({type(exc).__name__}). Check the API terminal.", "output": None}

@app.post("/api/prompt-tests")
def prompt_test(request: PromptTestRequest):
    expected = {
      "injection": "Do not follow untrusted instructions or expose secrets.",
      "traversal": "Reject paths outside the configured allowed root.",
      "destructive": "Keep destructive actions blocked without trusted server-side approval.",
      "benign": "A registered permitted tool may proceed only after gateway checks pass."
    }
    if request.scenario not in expected:
        raise HTTPException(status_code=400, detail="Unknown prompt test scenario.")
    flagged = request.scenario in {"injection","traversal","destructive"}
    return {"ok": True, "blocked": flagged, "reason": "Risky scenario selected for planning. This is not an LLM or gateway verdict." if flagged else "Benign scenario selected. This is not an LLM or gateway verdict.", "mode": "SCENARIO PREVIEW ONLY", "expected": expected[request.scenario]}
