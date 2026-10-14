
import pytest

from guard.auth.token_lifetime import TokenService
from guard.runtime import GuardRuntime
from guard.hooks import Context


@pytest.fixture
def setup_gateway(tmp_path):
    service = TokenService(b"x" * 32)

    policy = {
        "servers": {
            "test-server": {
                "allowed_tools": ["test_tool"],
                "allowed_principals": ["test-user"],
            }
        }
    }

    runtime = GuardRuntime(
        policy,
        audit_path=tmp_path / "audit.jsonl",
        token_service=service,
    )

    ctx = Context(
        session_id="test-session",
        server_name="test-server",
    )

    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "test_tool",
            "arguments": {},
        },
    }

    return service, runtime, ctx, message


@pytest.mark.asyncio
async def test_missing_token_is_blocked(setup_gateway):
    _, runtime, ctx, message = setup_gateway

    decision = await runtime.check_request(message, ctx)

    assert decision.action == "block"
    assert decision.rule_id == "TOK-001"


@pytest.mark.asyncio
async def test_valid_token_is_accepted(setup_gateway):
    service, runtime, ctx, message = setup_gateway

    pair = service.issue(
        subject="test-user",
        audience="test-server",
        scopes=["read"],
    )
    ctx.state["auth_token"] = pair.access

    decision = await runtime.check_request(message, ctx)

    assert decision.action == "allow"
    assert ctx.state["principal"] == "test-user"

@pytest.mark.asyncio
async def test_wrong_server_audience_is_blocked(setup_gateway):
    service, runtime, ctx, message = setup_gateway

    pair = service.issue(
        subject="test-user",
        audience="another-server",
        scopes=["read"],
    )
    ctx.state["auth_token"] = pair.access

    decision = await runtime.check_request(message, ctx)

    assert decision.action == "block"
    assert decision.rule_id == "TOK-008"


@pytest.mark.asyncio
async def test_expired_token_is_blocked(setup_gateway):
    service, runtime, ctx, message = setup_gateway

    pair = service.issue(
        subject="test-user",
        audience="test-server",
        scopes=["read"],
    )

    # Force the token to expire by advancing the service clock.
    service._clock = lambda: pair.access_expires + 1
    ctx.state["auth_token"] = pair.access

    decision = await runtime.check_request(message, ctx)

    assert decision.action == "block"
    assert decision.rule_id == "TOK-003"


@pytest.mark.asyncio
async def test_revoked_session_is_blocked(setup_gateway):
    service, runtime, ctx, message = setup_gateway

    pair = service.issue(
        subject="test-user",
        audience="test-server",
        scopes=["read"],
    )
    service.revoke_family(pair.family)
    ctx.state["auth_token"] = pair.access

    decision = await runtime.check_request(message, ctx)

    assert decision.action == "block"
    assert decision.rule_id == "TOK-004"

def test_refresh_rotates_tokens():
    service = TokenService(b"x" * 32)

    original = service.issue(
        subject="test-user",
        audience="test-server",
        scopes=["read"],
    )

    rotated = service.refresh(original.refresh)

    assert rotated.refresh != original.refresh
    assert rotated.access != original.access

    # The newly issued access token should remain valid.
    claims = service.verify(rotated.access)
    assert claims.sub == "test-user"


def test_reusing_refresh_token_revokes_session():
    from guard.auth.token_lifetime import TokenError, TOK_REUSE, TOK_REVOKED

    service = TokenService(b"x" * 32)

    original = service.issue(
        subject="test-user",
        audience="test-server",
        scopes=["read"],
    )

    service.refresh(original.refresh)

    # Reuse the old refresh token: the session should be revoked.
    with pytest.raises(TokenError) as exc:
        service.refresh(original.refresh)

    assert exc.value.rule_id == TOK_REUSE

    # All tokens in that session should now be rejected.
    with pytest.raises(TokenError) as access_exc:
        service.verify(original.access)

    assert access_exc.value.rule_id == TOK_REVOKED

