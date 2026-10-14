"""
guard/checks/path.py  --  Track B: path traversal check (CWE-22), pre-call.

What it does for every tools/call request:
  1. Walks ALL the arguments (any depth, dicts and lists).
  2. Fields that look like paths get the FULL check (steps below).
  3. Every other string gets a lighter "generic scan" as a second layer, in case a path
     is hiding under a field name we did not expect.

Full check on a path field:
  a. must be a non-empty string of sane length, with no null bytes
  b. normalize it (URL-decode, Unicode NFKC) and block multi-layer encoding
  c. reject Windows-style absolute paths / UNC / drive letters / ":" tricks
  d. join relative paths onto the allowed root, then .resolve() (collapses ".." and follows
     symlinks to the REAL location)
  e. the real location must be inside an allowed root (is_relative_to, never startswith)
  f. the part below the root must not touch sensitive names (.ssh, .env, *.pem ...)

Rule ids (stable, so logs / dashboard / benchmark line up):
  PATH-001 escapes allowed root      PATH-002 sensitive target       PATH-003 invalid value
  PATH-004 cannot resolve path       PATH-005 multi-layer encoding   PATH-006 suspicious text in
  PATH-007 no/too-broad roots                                        a non-path field
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from guard.checks.normalize import normalize_text
from guard.checks.context_access import get_input_schemas, get_policy, server_name
from guard.hooks import BLOCK, Context, Decision

# ---- rule ids -------------------------------------------------------------
PATH_ESCAPE = "PATH-001"
PATH_SENSITIVE = "PATH-002"
PATH_BAD_VALUE = "PATH-003"
PATH_UNRESOLVABLE = "PATH-004"
PATH_ENCODING = "PATH-005"
PATH_SUSPICIOUS_TEXT = "PATH-006"
PATH_NO_ROOTS = "PATH-007"

# ---- defaults (every one can be overridden in the policy file) ------------
# Argument names that normally hold a path.
DEFAULT_ARG_NAMES = ("path", "paths", "file", "files", "filename", "filepath", "file_path",
                     "dir", "directory", "folder", "src", "dst", "source", "destination",
                     "target", "cwd", "root")
# ...and name endings, so "output_path", "config_file" are caught too.
DEFAULT_ARG_SUFFIXES = ("_path", "_file", "_dir", "_directory", "_filename")
# JSON-Schema "format" values that mark a property as a path (a "schema hint").
DEFAULT_PATH_FORMATS = ("path", "file-path", "filepath")
# Names that must never be touched, matched against each path component (case-insensitive).
DEFAULT_SENSITIVE_NAMES = (".ssh", ".env", ".env.*", ".aws", ".gnupg", ".kube", ".docker",
                           ".netrc", ".npmrc", ".pypirc", ".git-credentials",
                           "id_rsa", "id_ed25519", "id_ecdsa", "*.pem", "*.key", "*.p12",
                           "credentials", "shadow", "passwd")
# Whole locations that are off limits even if an allowed root is broad enough to contain them.
DEFAULT_SENSITIVE_PREFIXES = ("/etc", "/proc", "/sys", "/dev", "/root", "/var/run/secrets")

_WIN_DRIVE = re.compile(r"^[A-Za-z]:")                       # C:\ or C:/
_TRAVERSAL = re.compile(r"(?:^|[^.\w])\.\.(?:[/\s]|$)")      # a standalone ".." segment
_TOKEN_SPLIT = re.compile(r"""[/\s'"=:;()]+""")              # split free text into words


def _short(value: Any, n: int = 60) -> str:
    """Truncated repr of an offending value, so logs/errors stay small and safe."""
    s = repr(value)
    return s if len(s) <= n else s[:n] + "...'"


def _matches_any(name: str, patterns: tuple[str, ...]) -> bool:
    """Case-insensitive wildcard match, e.g. '*.pem' matches 'Server.PEM'."""
    return any(fnmatch.fnmatch(name.lower(), p.lower()) for p in patterns)


@dataclass(frozen=True)
class PathSettings:
    """Settings for this check, read from policy['checks']['path'] (all optional)."""
    arg_names: frozenset[str]
    arg_suffixes: tuple[str, ...]
    path_formats: frozenset[str]
    sensitive_names: tuple[str, ...]
    sensitive_prefixes: tuple[str, ...]
    max_len: int
    max_decode_layers: int
    generic_scan: str            # what to do with a suspicious non-path field: "ask"|"block"|"off"

    @classmethod
    def from_policy(cls, policy: dict[str, Any]) -> "PathSettings":
        c = ((policy.get("checks") or {}).get("path")) or {}
        return cls(
            arg_names=frozenset(n.lower() for n in c.get("arg_names", DEFAULT_ARG_NAMES)),
            arg_suffixes=tuple(s.lower() for s in c.get("arg_suffixes", DEFAULT_ARG_SUFFIXES)),
            path_formats=frozenset(c.get("path_formats", DEFAULT_PATH_FORMATS)),
            sensitive_names=tuple(c.get("sensitive_names", DEFAULT_SENSITIVE_NAMES)),
            sensitive_prefixes=tuple(c.get("sensitive_prefixes", DEFAULT_SENSITIVE_PREFIXES)),
            max_len=int(c.get("max_len", 4096)),
            max_decode_layers=int(c.get("max_decode_layers", 1)),
            generic_scan=str(c.get("generic_scan", "ask")),
        )


@dataclass
class _Env:
    """Everything one request needs, gathered once so the recursive walk stays simple."""
    cfg: PathSettings
    roots: list[Path]               # resolved allowed roots for this server
    tool_fields: frozenset[str]     # per-tool override: extra argument names that are paths
    schema_props: dict[str, Any]    # the tool's inputSchema["properties"] (for format hints)


class PathCheck:
    """The hook. Register an instance of this in the hook chain."""
    name = "path"

    # ---- entry point called by the hook chain -----------------------------
    def on_request(self, msg: dict[str, Any], ctx: Context) -> Decision:
        if msg.get("method") != "tools/call":      # only tool calls carry arguments
            return Decision.allow()
        params = msg.get("params") or {}
        tool = str(params.get("name", ""))
        args = params.get("arguments") or {}

        policy = get_policy(ctx)
        server_cfg = (policy.get("servers") or {}).get(server_name(ctx)) or {}
        env = _Env(
            cfg=PathSettings.from_policy(policy),
            roots=[Path(r).resolve() for r in (server_cfg.get("allowed_roots") or [])],
            tool_fields=frozenset(str(f).lower()
                                  for f in ((server_cfg.get("path_args") or {}).get(tool) or [])),
            schema_props=(get_input_schemas(ctx).get(tool) or {}).get("properties") or {},
        )

        asks: list[Decision] = []
        hit = self._scan(args, "", "arguments", env, asks)
        if hit is not None:            # a BLOCK always wins
            return hit
        return asks[0] if asks else Decision.allow()   # otherwise first ASK, else ALLOW

    # ---- walk the arguments ------------------------------------------------
    def _scan(self, obj: Any, key: str, where: str, env: _Env, asks: list[Decision]) -> Decision | None:
        """
        Recursive walk. `key` is the nearest argument NAME above this value (lists inherit the
        name of the field that holds them), `where` is a readable location like arguments.items[0].src.
        Returns a BLOCK decision immediately, or appends ASK decisions to `asks`.
        """
        path_like = bool(key) and self._is_path_field(key, env)

        if isinstance(obj, dict):
            if path_like:   # a path must be a string (or list of strings), not an object
                return Decision.block(PATH_BAD_VALUE, f"{where}: path field must be a string")
            for k, v in obj.items():
                d = self._scan(v, str(k), f"{where}.{k}", env, asks)
                if d is not None:
                    return d
            return None

        if isinstance(obj, (list, tuple)):
            for i, item in enumerate(obj):
                d = self._scan(item, key, f"{where}[{i}]", env, asks)
                if d is not None:
                    return d
            return None

        # a single value (string, number, None, ...)
        if path_like:
            return self._check_path_value(obj, where, env)
        if isinstance(obj, str):
            d = self._generic_scan(obj, where, env.cfg)
            if d is not None:
                if d.action == BLOCK:
                    return d
                asks.append(d)
        return None

    def _is_path_field(self, key: str, env: _Env) -> bool:
        """Decide whether an argument NAME means 'this holds a path'. Three signals."""
        k = key.lower()
        if k in env.cfg.arg_names or k.endswith(env.cfg.arg_suffixes):   # 1. by name
            return True
        if k in env.tool_fields:                                          # 2. per-tool policy
            return True
        fmt = (env.schema_props.get(key) or {}).get("format", "")         # 3. schema hint
        return fmt in env.cfg.path_formats

    # ---- the full check for one path value ---------------------------------
    def _check_path_value(self, raw: Any, where: str, env: _Env) -> Decision | None:
        cfg = env.cfg

        # (a) basic sanity of the raw value
        if not isinstance(raw, str):
            return Decision.block(PATH_BAD_VALUE, f"{where}: path must be a string, got {type(raw).__name__}")
        if not raw.strip():
            return Decision.block(PATH_BAD_VALUE, f"{where}: empty path")
        if len(raw) > cfg.max_len:
            return Decision.block(PATH_BAD_VALUE, f"{where}: path longer than {cfg.max_len} chars")

        # we need roots to judge anything: no roots configured = fail closed
        if not env.roots:
            return Decision.block(PATH_NO_ROOTS, f"{where}: no allowed_roots configured for this server")
        if any(r == Path(r.anchor) for r in env.roots):     # e.g. "/" would allow everything
            return Decision.block(PATH_NO_ROOTS, f"{where}: an allowed root is too broad (filesystem root)")

        # (b) normalize, then judge the NORMALIZED value
        norm = normalize_text(raw)
        if "null_byte" in norm.flags:
            return Decision.block(PATH_BAD_VALUE, f"{where}: null byte in path {_short(raw)}")
        if norm.decode_layers > cfg.max_decode_layers or "decode_limit_reached" in norm.flags:
            return Decision.block(PATH_ENCODING,
                                  f"{where}: multi-layer encoded path {_short(raw)}")
        text = norm.value.replace("\\", "/")   # treat "\" as a separator (safe side)

        # (c) Windows-style tricks, which pathlib on Linux would treat as harmless relative names
       
        # (c) Reject UNC paths and drive-relative tricks.
        # Permit Windows absolute paths to proceed to the root-containment check.
        is_windows_absolute = bool(re.match(r"^[A-Za-z]:/", text))

        if text.startswith("//"):
            return Decision.block(
                PATH_ESCAPE,
                f"{where}: UNC absolute path {_short(raw)}",
            )

        if _WIN_DRIVE.match(text) and not is_windows_absolute:
            return Decision.block(
                PATH_ESCAPE,
                f"{where}: drive-relative path {_short(raw)}",
            )

        # Colons are forbidden in other path components.
        parts = text.split("/")
        for index, part in enumerate(parts):
            if ":" in part and not (index == 0 and is_windows_absolute):
                return Decision.block(
                    PATH_BAD_VALUE,
                    f"{where}: ':' in a path component {_short(raw)}",
                )

        # (d) resolve to the REAL location
        try:
            p = Path(text).expanduser() if text.startswith("~") else Path(text)
            full = p if p.is_absolute() else env.roots[0] / p   # relative -> under the first root
            resolved = full.resolve(strict=False)               # collapses '..', follows symlinks
        except (OSError, RuntimeError, ValueError):
            return Decision.block(PATH_UNRESOLVABLE, f"{where}: cannot resolve path {_short(raw)}")

        # (e) must be inside an allowed root (is_relative_to compares path PARTS, so
        #     /srv/sandbox-evil is correctly NOT inside /srv/sandbox)
        root = next((r for r in env.roots if resolved.is_relative_to(r)), None)
        if root is None:
            return Decision.block(PATH_ESCAPE, f"{where}: path escapes allowed roots {_short(raw)}")

        # (f) sensitive targets. Only look BELOW the root, so a root that happens to live
        #     under e.g. ~/.config does not block everything.
        for part in resolved.relative_to(root).parts:
            if _matches_any(part, cfg.sensitive_names):
                return Decision.block(PATH_SENSITIVE, f"{where}: sensitive path component {part!r}")
        for prefix in cfg.sensitive_prefixes:
            pre = Path(prefix).resolve()
            if resolved.is_relative_to(pre) and not root.is_relative_to(pre):
                return Decision.block(PATH_SENSITIVE, f"{where}: sensitive location {prefix}")
        return None

    # ---- the lighter scan for non-path fields -------------------------------
    def _generic_scan(self, raw: str, where: str, cfg: PathSettings) -> Decision | None:
        """
        Second layer: a string in a field we did NOT recognise as a path. It is only looked at
        if it contains a '/' (or starts with '~'), i.e. it could be a path. Hits are ASK by
        default (not BLOCK) because this field may just be file CONTENT or free text.
        """
        if cfg.generic_scan == "off":
            return None
        text = normalize_text(raw[:65536]).value.replace("\\", "/")
        if "/" not in text and not text.startswith("~"):
            return None
        reason = None
        if _TRAVERSAL.search(text):
            reason = "traversal segment '..'"
        else:
            for token in _TOKEN_SPLIT.split(text):
                if token and _matches_any(token, cfg.sensitive_names):
                    reason = f"sensitive name {token!r}"
                    break
        if reason is None:
            return None
        msg = f"{where}: {reason} in a non-path field {_short(raw)}"
        if cfg.generic_scan == "block":
            return Decision.block(PATH_SUSPICIOUS_TEXT, msg, "medium")
        return Decision.ask(PATH_SUSPICIOUS_TEXT, msg, "medium")


# The hook as t1's HookChain wants it: a plain function (msg, ctx) -> Decision.
_CHECK = PathCheck()


def path_hook(msg: dict[str, Any], ctx: Context) -> Decision:
    """Register this one in the chain: HookChain([..., path_hook, ...])."""
    return _CHECK.on_request(msg, ctx)
