
import asyncio
import tempfile
import unittest
from pathlib import Path

from Command_guard.guard.auth.token_lifetime import TokenService
from Command_guard.guard.hooks import ALLOW, BLOCK, Context
from Command_guard.guard.runtime import GuardRuntime
from Command_guard.guard.policy_loader import load_policy


class SecurityGatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.audit = self.root / "logs" / "audit.jsonl"

       
        self.policy = {
            "servers": {
                "filesystem": {
                    "allowed_tools": ["read_file"],
                    "allowed_principals": ["alice"],
                    "allowed_roots": [str(self.root.resolve())],
                }
            },
            "checks": {
                "command": {},
                "path": {"generic_scan": "ask"},
            },
        }


        # Use a dedicated test key, never a production key.
        self.token_service = TokenService(b"t" * 32)

        self.guard = GuardRuntime(
            self.policy,
            self.audit,
            token_service=self.token_service,
        )

        self.token_pair = self.token_service.issue(
            subject="alice",
            audience="filesystem",
            scopes=["read"],
        )

        self.ctx = Context(
            session_id="gateway-test",
            server_name="filesystem",
            state={
                "principal": "alice",
                "roles": ["reader"],
                "auth_token": self.token_pair.access,
            },
        )

    def tearDown(self):
        self.temp.cleanup()

    def request(self, tool="read_file", arguments=None):
        return {
            "jsonrpc": "2.0",
            "id": "gateway-test-1",
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": arguments or {"path": "notes.txt"},
            },
        }

    def check(self, message=None, ctx=None):
        return asyncio.run(
            self.guard.check_request(
                message or self.request(),
                ctx or self.ctx,
            )
        )

    def test_valid_token_and_allowed_tool(self):
        decision = self.check()
        self.assertEqual(decision.action, ALLOW)

    def test_missing_token_is_blocked(self):
        ctx = Context(
            session_id="missing-token",
            server_name="filesystem",
            state={"principal": "alice", "roles": ["reader"]},
        )
        decision = self.check(ctx=ctx)
        self.assertEqual(decision.action, BLOCK)

   
    def test_valid_token_and_allowed_tool(self):
        decision = self.check()

        print("\nAction:", decision.action)
        print("Rule ID:", getattr(decision, "rule_id", None))
        print("Reason:", getattr(decision, "reason", None))
        print("Full decision:", repr(decision))

        self.assertEqual(decision.action, ALLOW)
    

    def test_invalid_token_is_blocked(self):
        ctx = Context(
            session_id="invalid-token",
            server_name="filesystem",
            state={
                "principal": "alice",
                "roles": ["reader"],
                "auth_token": "not-a-valid-token",
            },
        )
        decision = self.check(ctx=ctx)
        self.assertEqual(decision.action, BLOCK)

    def test_audit_record_is_written(self):
        self.check()
        self.assertTrue(self.audit.exists())
        self.assertGreater(self.audit.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
