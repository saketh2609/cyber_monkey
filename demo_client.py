
import asyncio
import os
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROJECT_ROOT = Path(__file__).resolve().parent
SERVER_FILE = PROJECT_ROOT / "server.py"


async def main():
    env = os.environ.copy()

    if not env.get("MCP_GUARD_SIGNING_KEY"):
        print("ERROR: MCP_GUARD_SIGNING_KEY is missing.")
        return

    params = StdioServerParameters(
        command=sys.executable,
        args=["-u", str(SERVER_FILE)],
        cwd=str(PROJECT_ROOT),
        env=env,
    )

    try:
        async with stdio_client(
            params, errlog=sys.stderr
        ) as (read_stream, write_stream):

            async with ClientSession(
                read_stream, write_stream
            ) as session:

                print("Starting MCP handshake...", file=sys.stderr)

                result = await session.initialize()

                print("MCP handshake successful!")
                print("Server:", result.server_info)

                tools = await session.list_tools()

                print("\nRegistered tools:")
                for tool in tools.tools:
                    print("-", tool.name)

                print("\n--- HACKURITY SECURITY TESTS ---")

                # TEST 1: List files inside the sandbox
                print("\n[TEST 1] List sandbox files")

                try:
                    result = await session.call_tool(
                        "list_files",
                        {"path": "."},
                    )

                    print("Tool result:")
                    print(result)

                except Exception as exc:
                    print(
                        "Request failed:",
                        type(exc).__name__,
                        exc,
                    )

                # TEST 2: Attempt path traversal
                print("\n[TEST 2] Attempt path traversal")

                try:
                    result = await session.call_tool(
                        "read_file",
                        {"path": "../server.py"},
                    )

                    print("Tool result:")
                    print(result)

                except Exception as exc:
                    print(
                        "Request failed:",
                        type(exc).__name__,
                        exc,
                    )

                print("\n--- TESTS FINISHED ---")

    except Exception as exc:
        print(
            "\nCLIENT ERROR:",
            type(exc).__name__,
            exc,
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
