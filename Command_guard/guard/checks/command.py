"""
guard/checks/command.py  --  Track B: command injection check (CWE-78), pre-call.

The idea: a tool that runs a program (ping, git, ls, a "run command" tool...) must never run
something the policy did not explicitly allow. We use ALLOWLISTS, not blacklists, because
attackers bypass blacklists with encoding and rephrasing.

Three ways a call can be checked:

  Mode A - per-tool FIELD allowlist (policy: servers.<s>.command_fields).
      For tools like ping(host=...) where one value ends up inside a command. The value must
      fully match an allowed regex and must not start with "-" (argument injection).

  Mode B - COMMAND fields (named command/cmd/args/argv/...).
      We build an argv list ([program, arg1, arg2...]) and check:
        * the program is in policy servers.<s>.allowed_commands   (else CMD-003)
        * every "-flag" is in that program's allowed_flags          (else CMD-002)
        * every other argument matches the program's arg_pattern    (else CMD-001)
      A command given as ONE STRING is treated as if a shell will run it, so it may only use
      a tiny set of safe characters (letters, digits, space and  _ . / : = @ % + , -).
      Anything else (; | & $ ` < > ( ) { } newline quotes ...) is CMD-001.

  Generic scan (second layer) - any other string is checked for obvious injection shapes
      such as $(...), `...`, "; rm", "| sh". These are ASK by default because the text may
      just be file content.

Everything is normalized first (URL-decode, Unicode NFKC, null bytes), same as the path check.

Rule ids:
  CMD-001 unsafe characters / value does not match allowed pattern   (block)
  CMD-002 argument injection: flag not allowed / leading dash        (block)
  CMD-003 program not in allowed_commands                            (block)
  CMD-004 shell metacharacters inside an argv element                (ask)
  CMD-005 multi-layer encoding                                       (block)
  CMD-006 invalid value (wrong type, empty, null byte, too long...)  (block)
  CMD-007 command used but no allowlist configured / shell=true      (ask)
  CMD-008 injection-looking text in a non-command field              (ask | block | off)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from guard.checks.normalize import normalize_text
from guard.checks.context_access import get_policy, server_name
from guard.hooks import Context, Decision

CMD_UNSAFE = "CMD-001"
CMD_FLAG = "CMD-002"
CMD_NOT_ALLOWED = "CMD-003"
CMD_META_ARG = "CMD-004"
CMD_ENCODING = "CMD-005"
CMD_BAD_VALUE = "CMD-006"
CMD_NO_ALLOWLIST = "CMD-007"
CMD_SUSPICIOUS_TEXT = "CMD-008"

# Field names that hold the program or the whole command line.
DEFAULT_COMMAND_NAMES = ("command", "cmd", "executable", "program", "script",
                         "commandline", "command_line")
# Field names that hold extra arguments as a list.
DEFAULT_ARGS_NAMES = ("args", "argv", "arguments")
# Boolean fields that mean "run this through a shell" (shell=True style).
DEFAULT_SHELL_FLAGS = ("shell", "use_shell")

# The ONLY characters allowed in a command given as a single string (space = separator).
_SAFE_STRING = re.compile(r"[A-Za-z0-9_./:=@%+,\- ]+")
_SAFE_CHAR = re.compile(r"[A-Za-z0-9_./:=@%+,\- ]")
# Default allowlist for a single value in Mode A when the policy gives no pattern.
DEFAULT_FIELD_PATTERN = r"[A-Za-z0-9_.:/@%+,=-]+"
# Shell metacharacters (checked inside argv elements, where no shell *should* be involved).
_METACHARS = re.compile(r"[;|&$`<>(){}\n\r]")
# Obvious injection shapes for the generic second-layer scan (kept narrow on purpose).
_INJECTION_HINTS = (
    ("command substitution $(...)", re.compile(r"\$\(")),
    ("backtick command substitution", re.compile(r"`[^`\n]+`")),
    ("${IFS} whitespace trick", re.compile(r"\$\{IFS\}")),
    ("';' followed by a command",
     re.compile(r";\s*(?:rm|curl|wget|nc|ncat|bash|sh|zsh|cat|chmod|chown|python3?|perl|ruby)\b")),
    ("'&&' followed by a command",
     re.compile(r"&&\s*(?:rm|curl|wget|nc|ncat|bash|sh|zsh|cat|chmod|chown)\b")),
    ("pipe into a shell", re.compile(r"\|\s*(?:sh|bash|zsh|nc|ncat)\b")),
)


@lru_cache(maxsize=256)
def _rx(pattern: str) -> re.Pattern[str]:
    """Compile a policy-provided regex once. A bad pattern raises -> the chain fails closed."""
    return re.compile(pattern)


def _short(value: Any, n: int = 60) -> str:
    s = repr(value)
    return s if len(s) <= n else s[:n] + "...'"


@dataclass(frozen=True)
class CommandSettings:
    """Settings from policy['checks']['command'] (all optional)."""
    command_names: frozenset[str]
    args_names: frozenset[str]
    shell_flags: frozenset[str]
    max_len: int
    max_args: int
    max_decode_layers: int
    generic_scan: str            # "ask" | "block" | "off"

    @classmethod
    def from_policy(cls, policy: dict[str, Any]) -> "CommandSettings":
        c = ((policy.get("checks") or {}).get("command")) or {}
        return cls(
            command_names=frozenset(n.lower() for n in c.get("command_names", DEFAULT_COMMAND_NAMES)),
            args_names=frozenset(n.lower() for n in c.get("args_names", DEFAULT_ARGS_NAMES)),
            shell_flags=frozenset(n.lower() for n in c.get("shell_flags", DEFAULT_SHELL_FLAGS)),
            max_len=int(c.get("max_len", 2048)),
            max_args=int(c.get("max_args", 64)),
            max_decode_layers=int(c.get("max_decode_layers", 1)),
            generic_scan=str(c.get("generic_scan", "ask")),
        )


@dataclass
class _Env:
    """Everything one request needs, gathered once."""
    cfg: CommandSettings
    tool: str
    allowed: dict[str, dict[str, Any]]        # program -> {allowed_flags, arg_pattern}
    fields: dict[str, dict[str, Any]]         # Mode A: field name -> {pattern, ...} (this tool)


class CommandCheck:
    """The hook. Register an instance of this in the hook chain."""
    name = "command"

    def on_request(self, msg: dict[str, Any], ctx: Context) -> Decision:
        if msg.get("method") != "tools/call":
            return Decision.allow()
        params = msg.get("params") or {}
        tool = str(params.get("name", ""))
        args = params.get("arguments") or {}
        if not isinstance(args, dict):           # arguments should be an object; scan it anyway
            args = {"arguments": args}

        policy = get_policy(ctx)
        server_cfg = (policy.get("servers") or {}).get(server_name(ctx)) or {}
        env = _Env(
            cfg=CommandSettings.from_policy(policy),
            tool=tool,
            allowed={str(k): (v or {}) for k, v in (server_cfg.get("allowed_commands") or {}).items()},
            fields=((server_cfg.get("command_fields") or {}).get(tool)) or {},
        )

        asks: list[Decision] = []
        handled: set[str] = set()      # top-level fields already judged by Mode A / Mode B

        for step in (self._check_tool_fields, self._check_command_fields):
            d = step(args, env, asks, handled)
            if d is not None:          # a BLOCK always wins
                return d
        d = self._generic(args, "arguments", env, asks, handled, top=True)
        if d is not None:
            return d
        return asks[0] if asks else Decision.allow()

    # ---- Mode A: per-tool field allowlist ---------------------------------
    def _check_tool_fields(self, args, env, asks, handled) -> Decision | None:
        for field, spec in env.fields.items():
            key = next((k for k in args if k.lower() == field.lower()), None)
            if key is None:            # absent field: schema validation's job, not ours
                continue
            handled.add(key)
            spec = spec or {}
            where = f"arguments.{key}"
            v, d = self._norm(args[key], where, env.cfg)
            if d is not None:
                return d
            if not v.strip():
                return Decision.block(CMD_BAD_VALUE, f"{where}: empty value")
            if len(v) > int(spec.get("max_len", env.cfg.max_len)):
                return Decision.block(CMD_BAD_VALUE, f"{where}: value too long")
            if v.startswith("-") and not spec.get("allow_leading_dash"):
                return Decision.block(CMD_FLAG, f"{where}: value starts with '-' (would become a flag) {_short(args[key])}")
            if not _rx(spec.get("pattern") or DEFAULT_FIELD_PATTERN).fullmatch(v):
                return Decision.block(CMD_UNSAFE, f"{where}: value does not match the allowed pattern {_short(args[key])}")
        return None

    # ---- Mode B: command / args fields --------------------------------------
    def _check_command_fields(self, args, env, asks, handled) -> Decision | None:
        cfg = env.cfg
        for k, v in args.items():                  # shell=True style switches
            if k.lower() in cfg.shell_flags and v is True:
                handled.add(k)
                asks.append(Decision.ask(CMD_NO_ALLOWLIST, f"arguments.{k}: tool asked to run through a shell"))

        cmd_key = next((k for k in args if k.lower() in cfg.command_names), None)
        args_key = next((k for k in args if k.lower() in cfg.args_names), None)
        for k in (cmd_key, args_key):
            if k is not None:
                handled.add(k)
        if cmd_key is None and args_key is None:
            return None
        if not env.allowed:                         # deny by default: no allowlist -> human decides
            asks.append(Decision.ask(CMD_NO_ALLOWLIST,
                                     "command/args field used but no allowed_commands is configured for this server"))
            return None

        if cmd_key is not None:
            argv, d = self._build_argv(args[cmd_key], f"arguments.{cmd_key}", cfg)
            if d is not None:
                return d
        elif env.tool in env.allowed:               # args only: the tool name IS the program
            argv = [env.tool]
        else:
            asks.append(Decision.ask(CMD_NO_ALLOWLIST,
                                     "args given without a command field and tool name is not in allowed_commands"))
            return None
        if args_key is not None:
            extra, d = self._build_argv(args[args_key], f"arguments.{args_key}", cfg)
            if d is not None:
                return d
            argv = argv + extra
        return self._check_argv(argv, f"arguments.{cmd_key or args_key}", env, asks)

    def _check_argv(self, argv: list[str], where: str, env: _Env, asks: list[Decision]) -> Decision | None:
        """argv is already normalized. argv[0] is the program."""
        if not argv:
            return Decision.block(CMD_BAD_VALUE, f"{where}: empty command")
        if len(argv) > env.cfg.max_args:
            return Decision.block(CMD_BAD_VALUE, f"{where}: more than {env.cfg.max_args} arguments")

        exe = argv[0]
        spec = env.allowed.get(exe)       # exact match: "ls" does NOT allow "/tmp/evil/ls"
        if spec is None:
            return Decision.block(CMD_NOT_ALLOWED, f"{where}: program {_short(exe)} is not in allowed_commands")

        flags = set(spec.get("allowed_flags") or [])
        pattern = spec.get("arg_pattern")
        after_dd = False                  # after a literal "--", "-x" is data, not a flag
        for arg in argv[1:]:
            if not after_dd and arg == "--":
                after_dd = True
                continue
            if not after_dd and arg.startswith("-") and arg != "-":
                flag, eq, value = arg.partition("=")          # --opt=value -> check "--opt"
                if flag not in flags:
                    return Decision.block(CMD_FLAG, f"{where}: flag {_short(flag)} not allowed for {exe!r}")
                if eq and pattern and not _rx(pattern).fullmatch(value):
                    return Decision.block(CMD_UNSAFE, f"{where}: flag value {_short(value)} not allowed")
                continue
            if pattern:
                if not _rx(pattern).fullmatch(arg):
                    return Decision.block(CMD_UNSAFE, f"{where}: argument {_short(arg)} does not match allowed pattern")
            elif _METACHARS.search(arg):
                asks.append(Decision.ask(CMD_META_ARG, f"{where}: shell metacharacters in argument {_short(arg)}"))
        return None

    # ---- helpers ------------------------------------------------------------
    def _norm(self, value: Any, where: str, cfg: CommandSettings) -> tuple[str, Decision | None]:
        """Type/size/null/encoding checks + normalization for ONE string."""
        if not isinstance(value, str):
            return "", Decision.block(CMD_BAD_VALUE, f"{where}: must be a string, got {type(value).__name__}")
        if len(value) > cfg.max_len:
            return "", Decision.block(CMD_BAD_VALUE, f"{where}: longer than {cfg.max_len} chars")
        n = normalize_text(value)
        if "null_byte" in n.flags:
            return "", Decision.block(CMD_BAD_VALUE, f"{where}: null byte {_short(value)}")
        if n.decode_layers > cfg.max_decode_layers or "decode_limit_reached" in n.flags:
            return "", Decision.block(CMD_ENCODING, f"{where}: multi-layer encoded value {_short(value)}")
        return n.value, None

    def _build_argv(self, value: Any, where: str, cfg: CommandSettings) -> tuple[list[str], Decision | None]:
        """Turn a command STRING or an argv LIST into a normalized list of strings."""
        if isinstance(value, str):
            v, d = self._norm(value, where, cfg)
            if d is not None:
                return [], d
            if not v.strip():
                return [], Decision.block(CMD_BAD_VALUE, f"{where}: empty command")
            if not _SAFE_STRING.fullmatch(v):          # a single string = shell risk: strict allowlist
                bad = sorted({c for c in v if not _SAFE_CHAR.fullmatch(c)})[:5]
                return [], Decision.block(CMD_UNSAFE, f"{where}: unsafe characters {bad!r} in command string {_short(value)}")
            return v.split(), None
        if isinstance(value, (list, tuple)):
            out: list[str] = []
            for i, el in enumerate(value):
                v, d = self._norm(el, f"{where}[{i}]", cfg)
                if d is not None:
                    return [], d
                out.append(v)
            return out, None
        return [], Decision.block(CMD_BAD_VALUE, f"{where}: must be a string or a list, got {type(value).__name__}")

    # ---- generic second layer ------------------------------------------------
    def _generic(self, obj, where, env, asks, handled, top=False) -> Decision | None:
        if env.cfg.generic_scan == "off":
            return None
        if isinstance(obj, dict):
            for k, v in obj.items():
                if top and k in handled:               # already judged by Mode A / B
                    continue
                d = self._generic(v, f"{where}.{k}", env, asks, handled)
                if d is not None:
                    return d
        elif isinstance(obj, (list, tuple)):
            for i, item in enumerate(obj):
                d = self._generic(item, f"{where}[{i}]", env, asks, handled)
                if d is not None:
                    return d
        elif isinstance(obj, str):
            text = normalize_text(obj[:65536]).value
            for label, rx in _INJECTION_HINTS:
                if rx.search(text):
                    msg = f"{where}: {label} in a non-command field {_short(obj)}"
                    if env.cfg.generic_scan == "block":
                        return Decision.block(CMD_SUSPICIOUS_TEXT, msg, "medium")
                    asks.append(Decision.ask(CMD_SUSPICIOUS_TEXT, msg, "medium"))
                    break
        return None


# The hook as t1's HookChain wants it: a plain function (msg, ctx) -> Decision.
_CHECK = CommandCheck()


def command_hook(msg: dict[str, Any], ctx: Context) -> Decision:
    """Register this one in the chain: HookChain([..., command_hook, ...])."""
    return _CHECK.on_request(msg, ctx)
