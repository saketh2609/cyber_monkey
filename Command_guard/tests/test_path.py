import asyncio
import os
import tempfile
import unittest
from pathlib import Path

from guard.checks.normalize import normalize_text
from guard.checks.path import PathCheck, path_hook
from guard.hooks import ALLOW, ASK, BLOCK, Context, HookChain
from guard.policy_loader import load_policy

HERE = Path(__file__).resolve().parent


def req(args, tool="read_file", method="tools/call", rid=7):
    """Build a JSON-RPC tools/call request like the one the agent would send."""
    return {"jsonrpc": "2.0", "id": rid, "method": method,
            "params": {"name": tool, "arguments": args}}


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name).resolve()
        self.base = base
        self.root = base / "sandbox"
        self.root.mkdir()
        (self.root / "notes.txt").write_text("hi")
        (base / "secret.txt").write_text("secret")
        os.symlink(base / "secret.txt", self.root / "link_to_secret")   # symlink pointing OUTSIDE
        self.check = PathCheck()

    def tearDown(self):
        self._tmp.cleanup()

    def ctx(self, roots=None, checks=None, path_args=None, schemas=None):
        server = {"allowed_roots": [str(self.root)] if roots is None else roots}
        if path_args:
            server["path_args"] = path_args
        policy = {"servers": {"filesystem": server}, "checks": {"path": checks or {}}}
        return Context(session_id="test", server_name="filesystem",
                       state={"policy": policy, "input_schemas": schemas or {}})

    def run_check(self, args, **kw):
        ctx_keys = {k: kw.pop(k) for k in ("roots", "checks", "path_args", "schemas") if k in kw}
        return self.check.on_request(req(args, **kw), self.ctx(**ctx_keys))

    def assertBlocked(self, d, rule):
        self.assertEqual(d.action, BLOCK, d)
        self.assertEqual(d.rule_id, rule, d)


class AllowTests(Base):
    def test_normal_paths_pass(self):
        for p in ["notes.txt", "sub/new.txt", "./notes.txt", "file with spaces.txt",
                  "my.notes.v2.txt", "dots..in..name.txt", "100%.txt", "sub/../notes.txt"]:
            with self.subTest(path=p):
                self.assertIs(self.run_check({"path": p}).action, ALLOW)

    def test_absolute_path_inside_root_passes(self):
        self.assertIs(self.run_check({"path": str(self.root / "notes.txt")}).action, ALLOW)

    def test_other_methods_ignored(self):
        d = self.check.on_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, self.ctx())
        self.assertEqual(d.action, ALLOW)


class EscapeTests(Base):
    def test_escapes_blocked_001(self):
        cases = ["../secret.txt", "../../etc/passwd", "sub/../../secret.txt", "/etc/passwd",
                 "link_to_secret",                    # symlink escape
                 "..\\secret.txt",                    # backslash separator
                 "%2e%2e/secret.txt",                 # one layer of URL-encoding
                 "\uff0e\uff0e/secret.txt",           # fullwidth dots -> NFKC -> ".."
                 "C:\\Windows\\win.ini",              # drive letter
                 "C:notes",                           # drive-relative (Windows)
                 "\\\\server\\share\\x",              # UNC
                 "~/.ssh/id_rsa"]                     # home expansion
        for p in cases:
            with self.subTest(path=p):
                d = self.run_check({"path": p})
                self.assertBlocked(d, "PATH-001")

    def test_prefix_trick_blocked(self):
        evil = self.base / "sandbox-evil"
        evil.mkdir()
        self.assertBlocked(self.run_check({"path": str(evil / "x.txt")}), "PATH-001")

    def test_double_encoding_blocked_005(self):
        self.assertBlocked(self.run_check({"path": "%252e%252e/secret.txt"}), "PATH-005")


class BadValueTests(Base):
    def test_bad_values_003(self):
        for v in ["", "   ", "a\x00b", "notes.txt%00.png", "a" * 5000, 123, None,
                  {"x": "../y"}, "file.txt:stream"]:
            with self.subTest(value=repr(v)[:20]):
                self.assertBlocked(self.run_check({"path": v}), "PATH-003")

    def test_no_roots_or_root_too_broad_007(self):
        self.assertBlocked(self.run_check({"path": "a"}, roots=[]), "PATH-007")
        self.assertBlocked(self.run_check({"path": "a"}, roots=["/"]), "PATH-007")


class SensitiveTests(Base):
    def test_sensitive_names_002(self):
        for p in [".env", "sub/.ssh/id_rsa", "keys/server.pem", ".AWS/credentials", ".env.production"]:
            with self.subTest(path=p):
                self.assertBlocked(self.run_check({"path": p}), "PATH-002")

    def test_sensitive_prefix_inside_broad_root(self):
        d = self.run_check({"path": "private/x"},
                           checks={"sensitive_prefixes": [str(self.root / "private")]})
        self.assertBlocked(d, "PATH-002")


class FieldDetectionTests(Base):
    def test_nested_and_lists(self):
        self.assertBlocked(self.run_check({"items": [{"src": "notes.txt", "dst": "../x"}]}), "PATH-001")
        self.assertBlocked(self.run_check({"paths": ["notes.txt", "../x"]}), "PATH-001")

    def test_suffix_name_detected(self):
        self.assertBlocked(self.run_check({"output_path": "../x"}), "PATH-001")

    def test_schema_format_hint(self):
        schemas = {"open": {"properties": {"thing": {"type": "string", "format": "path"}}}}
        self.assertBlocked(self.run_check({"thing": "../x"}, tool="open", schemas=schemas), "PATH-001")

    def test_per_tool_override(self):
        d = self.run_check({"location": "../x"}, tool="read_file",
                           path_args={"read_file": ["location"]})
        self.assertBlocked(d, "PATH-001")


class GenericScanTests(Base):
    def test_suspicious_text_in_non_path_field_asks(self):
        for text in ["see ../../etc/passwd", "cat ~/.ssh/id_rsa"]:
            with self.subTest(text=text):
                d = self.run_check({"content": text})
                self.assertEqual(d.action, ASK)
                self.assertEqual(d.rule_id, "PATH-006")

    def test_harmless_text_passes(self):
        for text in ["hello world", "and/or", "https://example.com/docs", "wait..."]:
            with self.subTest(text=text):
                self.assertIs(self.run_check({"content": text}).action, ALLOW)

    def test_modes(self):
        self.assertBlocked(self.run_check({"content": "../../x"}, checks={"generic_scan": "block"}), "PATH-006")
        self.assertIs(self.run_check({"content": "../../x"}, checks={"generic_scan": "off"}).action, ALLOW)

    def test_block_beats_ask(self):
        d = self.run_check({"content": "../../x", "path": "../y"})
        self.assertBlocked(d, "PATH-001")


class NormalizeTests(unittest.TestCase):
    def test_layers_and_flags(self):
        self.assertEqual(normalize_text("%252e%252e/x").decode_layers, 2)
        self.assertEqual(normalize_text("%2e%2e/x").value, "../x")
        self.assertEqual(normalize_text("\uff0e\uff0e/x").value, "../x")
        n = normalize_text("a%00b")
        self.assertIn("null_byte", n.flags)
        self.assertEqual(n.value, "ab")
        self.assertEqual(normalize_text("plain.txt").decode_layers, 0)


class ChainTests(Base):
    """Run the hook through t1's REAL HookChain (async, deep-copies the message, fail closed)."""
    def run_chain(self, hooks, msg):
        return asyncio.run(HookChain(hooks).run(msg, self.ctx()))

    def test_blocks_through_real_hookchain(self):
        d = self.run_chain([path_hook], req({"path": "../secret.txt"}, rid=42))
        self.assertEqual((d.action, d.rule_id), (BLOCK, "PATH-001"))

    def test_allows_through_real_hookchain(self):
        d = self.run_chain([path_hook], req({"path": "notes.txt"}))
        self.assertEqual(d.action, ALLOW)

    def test_crashing_hook_fails_closed(self):
        def boom(msg, ctx):
            raise RuntimeError("x")
        d = self.run_chain([boom], req({}))
        self.assertEqual((d.action, d.rule_id), (BLOCK, "GUARD-HOOK-ERROR"))

    def test_malformed_arguments_fail_closed(self):
        # arguments is a list, not an object: whatever happens it must not be a plain ALLOW of an escape
        d = self.run_chain([path_hook], req(["../x"]))
        self.assertNotEqual(d.action, ALLOW)

    def test_missing_policy_blocks(self):
        # proxy forgot to put the policy in ctx.state -> no allowed roots -> fail closed
        ctx = Context(session_id="t", server_name="filesystem", state={})
        d = asyncio.run(HookChain([path_hook]).run(req({"path": "notes.txt"}), ctx))
        self.assertEqual((d.action, d.rule_id), (BLOCK, "PATH-007"))


class PolicyFileTests(unittest.TestCase):
    def test_sample_policy_loads(self):
        policy = load_policy(HERE.parent / "policy" / "policy.yaml")
        self.assertIn("filesystem", policy["servers"])


if __name__ == "__main__":
    unittest.main()
