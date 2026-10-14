
# security_policy.py

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


# ============================================================
# 1. CENTRAL SECURITY CONFIGURATION
# ============================================================

@dataclass(frozen=True)
class SecurityConfig:
    allowed_root: Path

    # Explicit allowlist: add only tools that your app needs.
    allowed_tools: frozenset[str] = frozenset({
        "read_file",
        "list_files",
        "write_file",
        "delete_file",
    })

    # Sensitive names are denied by default.
    blocked_names: frozenset[str] = frozenset({
        ".env",
        ".git",
        "secrets",
        "credentials",
        "id_rsa",
        "id_ed25519",
    })

    # Operations that require a trusted confirmation.
    destructive_tools: frozenset[str] = frozenset({
        "write_file",
        "delete_file",
    })


@dataclass(frozen=True)
class SecurityDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class TrustedConfirmation:
    # This object must be created by trusted application code,
    # not copied from AI output or untrusted document content.
    tool_name: str
    target: str
    approved: bool


# ============================================================
# 2. INSTRUCTION / DATA TRUST RULES
# ============================================================

def check_instruction_source(source: str) -> SecurityDecision:
    """
    External content can provide information, not permissions.
    Never promote document text into trusted policy.
    """
    untrusted_sources = {
        "file",
        "document",
        "web",
        "tool_output",
        "retrieved_content",
        "user_supplied_data",
    }

    if source not in untrusted_sources | {
        "trusted_application"
    }:
        return SecurityDecision(False, "Unknown instruction source.")

    return SecurityDecision(
        True,
        "Source classified; authorization is still required."
    )


def check_policy_integrity(
    requested_policy_change: bool,
    change_from_trusted_admin: bool,
) -> SecurityDecision:
    if requested_policy_change and not change_from_trusted_admin:
        return SecurityDecision(
            False,
            "Only trusted application administration can change policy."
        )

    return SecurityDecision(True, "Policy integrity check passed.")


# ============================================================
# 3. TOOL ALLOWLIST
# ============================================================

def check_tool(
    tool_name: str,
    config: SecurityConfig,
) -> SecurityDecision:
    if not isinstance(tool_name, str) or not tool_name:
        return SecurityDecision(False, "Invalid tool name.")

    if tool_name not in config.allowed_tools:
        return SecurityDecision(False, "Tool is not allowlisted.")

    return SecurityDecision(True, "Tool is allowlisted.")


# ============================================================
# 4. ARGUMENT VALIDATION
# ============================================================

def check_arguments(
    tool_name: str,
    arguments: Mapping[str, Any],
) -> SecurityDecision:
    if not isinstance(arguments, Mapping):
        return SecurityDecision(False, "Arguments must be a mapping.")

    if not all(isinstance(key, str) for key in arguments):
        return SecurityDecision(False, "Invalid argument names.")

    # Reject unexpected argument names rather than guessing.
    schemas = {
        "read_file": {"path"},
        "list_files": {"path"},
        "write_file": {"path", "content"},
        "delete_file": {"path"},
    }

    schema = schemas.get(tool_name)
    if schema is None:
        return SecurityDecision(False, "No schema for this tool.")

    if set(arguments.keys()) != schema:
        return SecurityDecision(
            False,
            "Missing or unexpected tool arguments."
        )

    if not isinstance(arguments.get("path"), str):
        return SecurityDecision(False, "Path must be a string.")

    if tool_name == "write_file":
        if not isinstance(arguments.get("content"), str):
            return SecurityDecision(False, "Content must be text.")

    return SecurityDecision(True, "Arguments are valid.")


# ============================================================
# 5. FILE PATH / RESOURCE BOUNDARY
# ============================================================

def resolve_authorized_path(
    requested_path: str,
    config: SecurityConfig,
) -> tuple[Path | None, SecurityDecision]:
    if not requested_path or "\x00" in requested_path:
        return None, SecurityDecision(False, "Invalid file path.")

    try:
        root = config.allowed_root.resolve(strict=True)

        if not root.is_dir():
            return None, SecurityDecision(
                False, "Authorized root is not a directory."
            )

        candidate = Path(requested_path)

        # Accept relative paths only. Do not let the model supply
        # an absolute path to access arbitrary locations.
        if candidate.is_absolute():
            return None, SecurityDecision(
                False, "Absolute paths are not permitted."
            )

        target = (root / candidate).resolve(strict=False)
        target.relative_to(root)

        # Deny sensitive path components.
        if any(
            part.lower() in {
                name.lower() for name in config.blocked_names
            }
            for part in candidate.parts
        ):
            return None, SecurityDecision(
                False, "Sensitive path is blocked."
            )

        # Reject existing symlinks in the requested path.
        current = root
        for part in candidate.parts:
            if part in {"", ".", ".."}:
                if part == "..":
                    return None, SecurityDecision(
                        False, "Path traversal is blocked."
                    )
                continue

            current = current / part

            if current.is_symlink():
                return None, SecurityDecision(
                    False, "Symbolic links are not permitted."
                )

        return target, SecurityDecision(
            True, "Path passed basic boundary checks."
        )

    except (ValueError, OSError, RuntimeError):
        return None, SecurityDecision(
            False, "Path could not be safely validated."
        )


# ============================================================
# 6. USER / RESOURCE AUTHORIZATION
# ============================================================

def check_authorization(
    authenticated_user_id: str | None,
    authorized_user_ids: frozenset[str],
    resource_is_authorized: bool,
) -> SecurityDecision:
    # The user identity must come from trusted application
    # authentication, never from an AI-generated argument.
    if not authenticated_user_id:
        return SecurityDecision(False, "User is not authenticated.")

    if authenticated_user_id not in authorized_user_ids:
        return SecurityDecision(False, "User is not authorized.")

    if resource_is_authorized is not True:
        return SecurityDecision(False, "Resource access is denied.")

    return SecurityDecision(True, "Authorization passed.")


# ============================================================
# 7. DESTRUCTIVE ACTION CONFIRMATION
# ============================================================

def check_confirmation(
    tool_name: str,
    target: Path,
    config: SecurityConfig,
    confirmation: TrustedConfirmation | None,
) -> SecurityDecision:
    if tool_name not in config.destructive_tools:
        return SecurityDecision(True, "Confirmation not required.")

    if confirmation is None or confirmation.approved is not True:
        return SecurityDecision(False, "Trusted confirmation required.")

    # Bind confirmation to the exact operation and canonical target.
    if confirmation.tool_name != tool_name:
        return SecurityDecision(False, "Confirmation tool mismatch.")

    if confirmation.target != str(target):
        return SecurityDecision(False, "Confirmation target mismatch.")

    return SecurityDecision(True, "Confirmation matches the target.")


# ============================================================
# 8. CENTRAL POLICY GATEWAY
# ============================================================

def authorize_tool_call(
    *,
    tool_name: str,
    arguments: Mapping[str, Any],
    config: SecurityConfig,
    authenticated_user_id: str | None,
    authorized_user_ids: frozenset[str],
    resource_is_authorized: bool,
    confirmation: TrustedConfirmation | None = None,
) -> tuple[Path | None, SecurityDecision]:

    # Every check fails closed: any failure blocks execution.
    decision = check_tool(tool_name, config)
    if not decision.allowed:
        return None, decision

    decision = check_arguments(tool_name, arguments)
    if not decision.allowed:
        return None, decision

    decision = check_authorization(
        authenticated_user_id,
        authorized_user_ids,
        resource_is_authorized,
    )
    if not decision.allowed:
        return None, decision

    target, decision = resolve_authorized_path(
        arguments["path"], config
    )
    if not decision.allowed or target is None:
        return None, decision

    decision = check_confirmation(
        tool_name, target, config, confirmation
    )
    if not decision.allowed:
        return None, decision

    return target, SecurityDecision(
        True, "All gateway checks passed."
    )
