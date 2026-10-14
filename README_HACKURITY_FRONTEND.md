# Hackurity frontend bundle

Adds a React/Vite dark dashboard and a localhost FastAPI bridge. Extract into the existing `W_H` root and merge `frontend/` and `frontend_api/`. Do not replace `Implement/`, `Command_guard/`, or `tests/`.

## Start the backend API

From the `W_H` project root, in terminal A:

```powershell
python -m pip install fastapi uvicorn
$env:HACKURITY_USER_ID = "user_1"
$env:HACKURITY_AUTHORIZED_USER_IDS = "user_1"
python -m uvicorn frontend_api.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/api/health` to see the configured local root and principal. The API creates `W_H/demo_workspace/notes.txt`.

Before testing live tool calls, set `servers.filesystem.allowed_roots` in `Command_guard/policy/policy.yaml` to the exact demo workspace path shown by health, and ensure `allowed_principals` includes the configured `HACKURITY_USER_ID`. Keep roots narrowly scoped; do not use a whole drive. Both Hackurity's `SecurityConfig` and Command Guard policy must permit the same target.

## Start the React frontend

In terminal B, from `W_H`:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173`.

## What's real and what's preview?

- Dashboard cards/events are seeded demo data unless populated by future trusted backend telemetry.
- Tool Inspector sends requests to `POST /api/tool-calls`, which calls your existing `execute_tool_call()` for permitted non-destructive tool calls when configured correctly.
- The bridge blocks `write_file`, `delete_file`, and `move_file`. Do not remove this restriction until a trusted server-side approval workflow is implemented. Never accept a browser-provided `TrustedConfirmation` as trusted.
- Prompt Lab is a scenario preview only. It does not invoke an LLM, submit prompts to the gateway, or execute tools.
- Audit Events is browser-session/seeded data, not a persistent audit-log reader.
- The API uses a configured local principal and has no user login. Keep it bound to localhost; do not expose it publicly. Production use requires authentication, authorization, and security hardening.

## Troubleshooting

- `npm` not found: install Node.js LTS, reopen terminal, check `node --version` and `npm --version`.
- `No module named Implement`: run Uvicorn from `W_H`, not from `frontend`.
- Calls blocked: compare `/api/health`'s allowed root/principal with Command Guard `allowed_roots`/`allowed_principals`. Inspect API terminal for diagnostics.
