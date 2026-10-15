# Hackurity API-Connected Test Lab

This is a replacement frontend plus a small FastAPI bridge. It does not include or replace your existing `Implement/` or `Command_guard/` folders. Copy `frontend_api/main.py` and `frontend_api/__init__.py` into your existing `W_H/frontend_api/`, and use the provided `frontend/` as the frontend folder.

## Important security boundary
- This local demo hardcodes a demo identity and authorizes it for the demo root. It is NOT production authentication.
- Do not expose the server publicly.
- write_file, delete_file, and move_file are blocked at the API boundary because this sample does not implement trusted server-side confirmation.
- The Python gateway requires `MCP_GUARD_SIGNING_KEY` at startup. Set it in the same PowerShell terminal before starting Uvicorn. Do not commit or share the key.
- If your actual module import is not `Implement.rules`, adjust only after checking where your existing `SecurityConfig` lives. Do not create duplicate rules modules.
- Prompt injection and output-inspection fixtures are screened with local frontend heuristics, not the Command Guard. They are labelled as heuristic.
- The 800 rows are 100 per category, generated as variations of a small set of templates. They are a demo suite, not an independently authored or validated benchmark.

## Setup
1. Copy the included `frontend_api` files into `W_H/frontend_api/`. Keep your existing `Implement/` and `Command_guard/`.
2. Copy the included `frontend` folder into `W_H/` (back up your current folder first if you want to preserve it).
3. In a PowerShell terminal at `W_H`, install API dependencies:
   `python -m pip install fastapi uvicorn pydantic`
4. Set a fresh local signing key in that same PowerShell terminal:
   `$env:MCP_GUARD_SIGNING_KEY = python -c "import secrets; print(secrets.token_hex(32))"`
   This key is temporary for this terminal session. Never paste it into chat or commit it.
5. Start the API from `W_H`:
   `python -m uvicorn frontend_api.main:app --host 127.0.0.1 --port 8000`
6. In a second terminal:
   `cd .\frontend`
   `npm.cmd install`
   `npm.cmd run dev`
7. Open the localhost URL Vite prints. API health is at `http://127.0.0.1:8000/api/health`; interactive docs are at `http://127.0.0.1:8000/docs`.

## Testing
- Start with one `read_file` case against `notes.txt`.
- Then run small groups before running all 800.
- A sample is marked MATCH when observed ALLOW/BLOCK matches its expected label. A match is not a proof of security.
