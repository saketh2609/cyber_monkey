from Command_guard.guard.auth.token_lifetime import TokenService
import tempfile
import unittest
from pathlib import Path

from Implement.mcp_defense import execute_tool_call
from Implement.rules import SecurityConfig, TrustedConfirmation


class RuntimeIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        (self.root / "notes.txt").write_text(
            "Hackurity test file.",
            encoding="utf-8",
        )

        self.config = SecurityConfig(allowed_root=self.root)
        self.users = frozenset({"user_1"})
        self.token_service = TokenService(b"x" * 32)
        self.token_pair = self.token_service.issue(
            subject="user_1",
            audience="filesystem",
            scopes=["read", "write"],
        )

        self.access_token = self.token_pair.access

    def tearDown(self):
        self.temp_dir.cleanup()

    
    def call_tool(self, tool_name, arguments, **overrides):
        options = {
            "authenticated_user_id": "user_1",
            "authorized_user_ids": self.users,
            "resource_is_authorized": True,
            "access_token": self.access_token,
            "token_service": self.token_service,
        }
        options.update(overrides)

        return execute_tool_call(
            tool_name=tool_name,
            arguments=arguments,
            config=self.config,
            **options,
        )

    def test_authorized_read(self):
        result = self.call_tool(
            "read_file", {"path": "notes.txt"}
        )
        self.assertTrue(result["ok"], msg=result["reason"])
        self.assertEqual(result["output"], "Hackurity test file.")

    def test_unknown_tool_blocked(self):
        result = self.call_tool(
            "run_shell", {"command": "echo test"}
        )
        self.assertTrue(result["blocked"])

    def test_invalid_arguments_blocked(self):
        result = self.call_tool(
            "read_file", {"path": "notes.txt", "extra": True}
        )
        self.assertTrue(result["blocked"])

    def test_unauthenticated_call_blocked(self):
        result = self.call_tool(
            "read_file",
            {"path": "notes.txt"},
            authenticated_user_id=None,
        )
        self.assertTrue(result["blocked"])

    def test_path_traversal_blocked(self):
        result = self.call_tool(
            "read_file", {"path": "../secret.txt"}
        )
        self.assertTrue(result["blocked"])

   
    def test_file_write(self):
        target = str((self.root / "new.txt").resolve())

        confirmation = TrustedConfirmation(
            tool_name="write_file",
            target=target,
            approved=True,
        )

        result = self.call_tool(
            "write_file",
            {"path": "new.txt", "content": "safe test"},
            confirmation=confirmation,
        )

        self.assertTrue(result["ok"], msg=result["reason"])



if __name__ == "__main__":
    unittest.main(verbosity=2)