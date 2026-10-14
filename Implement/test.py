#hackurity project proxy defense system
#
# THE GATEWAY.
# Every tool call the AI wants to make is sent through security_proxy() first.
# The gateway runs the rule functions from rules.py and answers:
#     {"allowed": True,  "reason": "...", "target": <safe file path>}
#     {"allowed": False, "reason": "...", "target": None}
#
# This file contains no rules of its own. The rules live in rules.py:
#     check_instruction_source   where did the request come from?
#     check_policy_integrity     is someone trying to change the policy?
#     authorize_tool_call        tool allowlist, arguments, user permission,
#                                file path boundary, destructive confirmation
#
# The gateway fails closed: if anything goes wrong, the request is blocked.
#
# HOW TO USE:
#     result = security_proxy(
#         tool_name="read_file",
#         arguments={"path": "notes.txt"},
#         config=SecurityConfig(allowed_root=Path("/safe/folder")),
#         authenticated_user_id="user_1",
#         authorized_user_ids=frozenset({"user_1"}),
#         resource_is_authorized=True,
#     )
#     if not result["allowed"]:
#         ...stop here, do NOT run the tool...
#     else:
#         ...run the tool on result["target"]...

# Load the rules. If they cannot be loaded the gateway blocks everything.
try:
    from rules import (
        check_instruction_source,
        check_policy_integrity,
        authorize_tool_call,
    )
    RULES_LOADED = True
except Exception as error:
    print(f"Warning: could not load rules.py ({error}). The gateway will block every request.")
    RULES_LOADED = False


def blocked(reason):
    return {"allowed": False, "reason": reason, "target": None}


def security_proxy(
    *,
    tool_name,
    arguments,
    config,
    authenticated_user_id,
    authorized_user_ids,
    resource_is_authorized,
    confirmation=None,
    source="user_supplied_data",
    requested_policy_change=False,
    change_from_trusted_admin=False,
):
    # Fail closed if the rules could not be loaded
    if not RULES_LOADED:
        return blocked("Rules not loaded")

    try:
        # Rule: where did this request come from?
        decision = check_instruction_source(source)
        if not decision.allowed:
            return blocked(decision.reason)

        # Rule: only a trusted admin may change the policy
        decision = check_policy_integrity(requested_policy_change, change_from_trusted_admin)
        if not decision.allowed:
            return blocked(decision.reason)

        # Rules: tool allowlist, arguments, user permission, file path, confirmation
        target, decision = authorize_tool_call(
            tool_name=tool_name,
            arguments=arguments,
            config=config,
            authenticated_user_id=authenticated_user_id,
            authorized_user_ids=authorized_user_ids,
            resource_is_authorized=resource_is_authorized,
            confirmation=confirmation,
        )
    except Exception:
        # Any unexpected error blocks the request (fail closed)
        return blocked("Security check failed unexpectedly")

    if not decision.allowed:
        return blocked(decision.reason)

    return {"allowed": True, "reason": decision.reason, "target": target}


# =========================================================
# TEST VALUES ONLY (not part of the gateway)
# Everything below is for checking the gateway by hand.
# Delete this whole block when you are done testing.
# Run this file with:  python security_proxy.py
# =========================================================
if __name__ == "__main__":
    import tempfile
    from pathlib import Path
    from rules import SecurityConfig, TrustedConfirmation

    # TEST VALUE: a temporary folder that acts as the "allowed folder"
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder).resolve()

        # TEST VALUE: a sample file inside the allowed folder
        (root / "notes.txt").write_text("hello")

        # TEST VALUE: the security config, pointed at the temporary folder
        config = SecurityConfig(allowed_root=root)

        # TEST VALUE: the full path of the sample file (used for confirmations)
        notes_path = str((root / "notes.txt").resolve())

        # TEST VALUE: a normal, valid request. Each test below changes part of it.
        base_request = dict(
            tool_name="read_file",
            arguments={"path": "notes.txt"},
            config=config,
            authenticated_user_id="user_1",
            authorized_user_ids=frozenset({"user_1"}),
            resource_is_authorized=True,
        )

        # TEST VALUES: each test is (description, what to change, should it be allowed?)
        tests = [
            ("Normal read of notes.txt",           {},                                              True),
            ("Unknown tool (run_shell)",           {"tool_name": "run_shell"},                      False),
            ("Unexpected extra argument",          {"arguments": {"path": "notes.txt", "x": "1"}},  False),
            ("User not logged in",                 {"authenticated_user_id": None},                 False),
            ("User not on the authorized list",    {"authenticated_user_id": "hacker"},             False),
            ("Resource not authorized",            {"resource_is_authorized": False},               False),
            ("Path traversal (../secret.txt)",     {"arguments": {"path": "../secret.txt"}},        False),
            ("Absolute path (/etc/passwd)",        {"arguments": {"path": "/etc/passwd"}},          False),
            ("Sensitive file (.env)",              {"arguments": {"path": ".env"}},                 False),
            ("Delete with no confirmation",        {"tool_name": "delete_file"},                    False),
            ("Delete with matching confirmation",  {"tool_name": "delete_file",
                                                    "confirmation": TrustedConfirmation("delete_file", notes_path, True)}, True),
            ("Delete, confirmation for other file", {"tool_name": "delete_file",
                                                    "confirmation": TrustedConfirmation("delete_file", notes_path + "x", True)}, False),
            ("Unknown instruction source",         {"source": "random_source"},                     False),
            ("Untrusted policy change request",    {"requested_policy_change": True},               False),
        ]

        for description, changes, should_be_allowed in tests:
            result = security_proxy(**{**base_request, **changes})
            verdict = "ALLOWED" if result["allowed"] else "BLOCKED"
            check = "ok" if result["allowed"] == should_be_allowed else "MISMATCH"
            print(f"[{check}] {verdict:7} {description:38} -> {result['reason']}")