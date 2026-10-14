
"""Hackurity: MCP server protected by the security gateway."""

import asyncio
import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from Command_guard.guard.auth.token_lifetime import TokenService
from Implement.mcp_defense import execute_tool_call
from Implement.rules import SecurityConfig


PROJECT_ROOT = Path(__file__).resolve().parent
SANDBOX_ROOT = (PROJECT_ROOT / "sandbox").resolve()

# Demo identities must be established by trusted application code.
# Do not accept an identity directly from tool arguments.
DEMO_USER = os.environ.get("HACKURITY_DEMO_USER", "user_1")

# Configure the sandbox before starting the server.
if SANDBOX_ROOT.exists() and not SANDBOX_ROOT.is_dir():
    raise RuntimeError("Sandbox path exists but is not a directory.")

SANDBOX_ROOT.mkdir(parents=True, exist_ok=True)
# TokenService.from_env() requires MCP_GUARD_SIGNING_KEY to be configured.

TOKEN_SERVICE = TokenService.from_env()

# Issue a short-lived access token for the local demo user.
# Keep this TokenService instance alive for the entire server run.
TOKEN_PAIR = TOKEN_SERVICE.issue(
    subject=DEMO_USER,
    audience="filesystem",
    scopes=["read"],
)

SECURITY_CONFIG = SecurityConfig(allowed_root=SANDBOX_ROOT)
AUTHORIZED_USERS = frozenset({DEMO_USER})


server = MCPServer(
    name="Hackurity Security Gateway",
    version="0.1.0",
    instructions=(
        "Filesystem tools are protected by the Hackurity security gateway. "
        "Only authorized operations inside the configured sandbox are allowed."
    ),
)



def invoke_guarded_tool(tool_name: str, arguments: dict) -> dict:
    """Route a tool request through Hackurity before executing it."""

    result = execute_tool_call(
        tool_name=tool_name,
        arguments=arguments,
        config=SECURITY_CONFIG,
        authenticated_user_id=DEMO_USER,
        access_token=TOKEN_PAIR.access,
        token_service=TOKEN_SERVICE,
        authorized_user_ids=AUTHORIZED_USERS,
        resource_is_authorized=True,
        confirmation=None,
    )

    return result



@server.tool()
def read_file(path: str) -> dict:
    """Read a file inside the Hackurity sandbox."""
    return invoke_guarded_tool("read_file", {"path": path})


@server.tool()
def list_files(path: str = ".") -> dict:
    """List entries in a directory inside the Hackurity sandbox."""
    return invoke_guarded_tool("list_files", {"path": path})


@server.tool()
def write_file(path: str, content: str) -> dict:
    """Write a file inside the sandbox when trusted confirmation is available."""
    return invoke_guarded_tool(
        "write_file",
        {"path": path, "content": content},
    )


@server.tool()
def delete_file(path: str) -> dict:
    """Delete a sandbox file when trusted confirmation is available."""
    return invoke_guarded_tool("delete_file", {"path": path})


async def main() -> None:
    await server.run_stdio_async()


if __name__ == "__main__":
    asyncio.run(main())
