"""
guard/auth/token_lifetime.py  --  control 2 of 3: SHORT-LIVED tokens + ROTATION.

Problem it limits: a stolen OAuth token. A stolen token is only useful for as long as it lives,
so we make access tokens live for minutes, make refresh tokens single-use (rotation), and
detect when a refresh token is used twice (that means someone copied it) and kill the session.

What is in here
  TokenService     issues / verifies / refreshes / revokes tokens (HMAC-signed, JWT-shaped)
  authenticate()   the one function all three auth hooks use to check "is this token good?"
  make_lifetime_hook(service)   a hook for t1's HookChain that blocks bad/expired tokens

Rule ids (this file):
  TOK-001 no token presented              TOK-005 wrong token type (refresh used as access...)
  TOK-002 malformed / bad signature       TOK-006 refresh-token reuse detected (session killed)
  TOK-003 expired                         TOK-007 access token lives longer than allowed
  TOK-004 revoked / unknown session

How the proxy (t1) must use it
  * put the bearer token of the CURRENT request in  ctx.state["auth_token"]
  * keep the same TokenService object for the whole run (it holds the session/revocation state)

HONEST LIMITS
  * This is a stdlib stand-in that behaves like OAuth access/refresh tokens. In production the
    tokens come from a real authorization server and you verify them with a vetted JWT library.
  * State (sessions, revocations) is in memory: restart = everyone must log in again (fail closed).
  * It cannot stop a token being STOLEN. It only shrinks how long a stolen token is useful.
    Keep tokens off disk/logs and only send them over TLS.
"""
from __future__ import annotations
from Command_guard.guard.hooks import Context, Decision


import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from Command_guard.guard.hooks import Context, Decision

TOK_MISSING = "TOK-001"
TOK_INVALID = "TOK-002"
TOK_EXPIRED = "TOK-003"
TOK_REVOKED = "TOK-004"
TOK_WRONG_TYPE = "TOK-005"
TOK_REUSE = "TOK-006"
TOK_TTL = "TOK-007"

_CLOCK_SKEW_S = 30                                  # tolerated clock difference
_SCOPE_RE = re.compile(r"[a-z][a-z0-9_:.\-]{0,31}")  # scope names: "read", "write", "exec"...
_NAME_RE = re.compile(r"[^\s\x00-\x1f]{1,200}")      # subject / audience: no spaces or control chars


class TokenError(Exception):
    """A token problem. `rule_id` is one of the codes above (or AUD-/PRIV- from the other files)."""

    def __init__(self, rule_id: str, reason: str) -> None:
        super().__init__(f"{rule_id}: {reason}")
        self.rule_id = rule_id
        self.reason = reason


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# The header is a CONSTANT and must match exactly when verifying. That pins the algorithm
# (HS256) and removes the classic "alg: none" / algorithm-confusion attacks.
_HEADER_B64 = _b64e(b'{"alg":"HS256","typ":"JWT"}')


@dataclass(frozen=True)
class Claims:
    """The verified contents of a token."""
    sub: str                 # who the token was issued to
    aud: str                 # the ONE server it is valid for (audience binding uses this)
    scopes: tuple[str, ...]  # what it may do (least privilege uses this)
    iat: int                 # issued at (unix seconds)
    exp: int                 # expires at
    jti: str                 # unique token id
    typ: str                 # "access" or "refresh"
    fam: str                 # session ("family") id: revoking it kills every token in the session
    act: str = ""            # set on exchanged/elevated tokens: who they were derived by


@dataclass(frozen=True)
class TokenPair:
    access: str
    refresh: str
    access_expires: int
    refresh_expires: int
    family: str


@dataclass
class _Family:
    """Server-side record of one login session."""
    current_refresh: str     # jti of the ONLY refresh token that is still valid
    session_end: int         # hard cap: rotation can never extend a session past this
    revoked: bool = False


class TokenService:
    ISSUER = "mcp-guard"

    def __init__(self, secret: bytes, *, access_ttl: int = 300, refresh_ttl: int = 3600,
                 max_session: int = 86400, clock: Callable[[], float] = time.time) -> None:
        if not isinstance(secret, (bytes, bytearray)) or len(secret) < 32:
            raise ValueError("signing secret must be at least 32 random bytes")
        if min(access_ttl, refresh_ttl, max_session) <= 0:
            raise ValueError("lifetimes must be positive")
        self._secret = bytes(secret)
        self.access_ttl = access_ttl        # access tokens live this long (default 5 minutes)
        self.refresh_ttl = refresh_ttl      # each refresh token lives this long
        self.max_session = max_session      # absolute session cap, however often you refresh
        self._clock = clock
        self._lock = threading.RLock()      # hooks run in threads
        self._families: dict[str, _Family] = {}

    @classmethod
    def from_env(cls, var: str = "MCP_GUARD_SIGNING_KEY", **kwargs: Any) -> "TokenService":
        """Read the signing key from an environment variable. No key = refuse to start."""
        raw = os.environ.get(var)
        if not raw:
            raise RuntimeError(f"{var} is not set; refusing to run without a signing key")
        return cls(raw.encode(), **kwargs)

    def now(self) -> int:
        return int(self._clock())

    # ---- issuing --------------------------------------------------------------
    def issue(self, subject: str, audience: str, scopes: Iterable[str] = ("read",)) -> TokenPair:
        """Start a session: returns a short-lived access token + a single-use refresh token."""
        subject, audience = self._name(subject, "subject"), self._name(audience, "audience")
        scopes = self._scopes(scopes)
        with self._lock:
            now = self.now()
            self._prune(now)
            fam = secrets.token_urlsafe(12)
            session_end = now + self.max_session
            access, _, a_exp = self._mint("access", subject, audience, scopes, self.access_ttl, fam)
            refresh, r_jti, r_exp = self._mint("refresh", subject, audience, scopes,
                                               min(self.refresh_ttl, self.max_session), fam)
            self._families[fam] = _Family(current_refresh=r_jti, session_end=session_end)
            return TokenPair(access, refresh, a_exp, r_exp, fam)

    def mint_access(self, subject: str, audience: str, scopes: Iterable[str], *, family: str,
                    ttl: int | None = None, actor: str = "") -> str:
        """
        Mint an extra short-lived ACCESS token inside an existing session. Used for token exchange
        (audience.py) and temporary grants (least_privilege.py). It can never outlive the access
        TTL or the session, and it dies when the session is revoked.
        """
        subject, audience = self._name(subject, "subject"), self._name(audience, "audience")
        scopes = self._scopes(scopes)
        with self._lock:
            fam = self._families.get(family)
            if fam is None or fam.revoked:
                raise TokenError(TOK_REVOKED, "session is revoked or unknown")
            now = self.now()
            ttl = self.access_ttl if ttl is None else min(int(ttl), self.access_ttl)
            ttl = min(ttl, fam.session_end - now)
            if ttl <= 0:
                raise TokenError(TOK_EXPIRED, "session lifetime exceeded")
            token, _, _ = self._mint("access", subject, audience, scopes, ttl, family, actor)
            return token

    # ---- rotation -------------------------------------------------------------
    def refresh(self, refresh_token: str) -> TokenPair:
        """
        Trade a refresh token for a NEW access + refresh pair. The old refresh token stops working.
        If an old one is shown again, somebody copied it: revoke the whole session.
        """
        claims = self.verify(refresh_token, expected_type="refresh")
        with self._lock:
            fam = self._families[claims.fam]
            if claims.jti != fam.current_refresh:          # replay of an already-used token
                fam.revoked = True
                raise TokenError(TOK_REUSE, "refresh token reuse detected; session revoked")
            remaining = fam.session_end - self.now()
            if remaining <= 0:
                raise TokenError(TOK_EXPIRED, "session lifetime exceeded")
            access, _, a_exp = self._mint("access", claims.sub, claims.aud, claims.scopes,
                                          min(self.access_ttl, remaining), claims.fam)
            refresh, r_jti, r_exp = self._mint("refresh", claims.sub, claims.aud, claims.scopes,
                                               min(self.refresh_ttl, remaining), claims.fam)
            fam.current_refresh = r_jti
            return TokenPair(access, refresh, a_exp, r_exp, claims.fam)

    def revoke_family(self, family: str) -> None:
        """Kill a whole session: every access, refresh, exchanged and elevated token in it."""
        with self._lock:
            fam = self._families.get(family)
            if fam is not None:
                fam.revoked = True

    # ---- verifying ------------------------------------------------------------
    def verify(self, token: Any, expected_type: str = "access") -> Claims:
        """Return the claims of a good token, or raise TokenError saying why it is not good."""
        claims = self._parse(token)
        if claims.typ != expected_type:
            raise TokenError(TOK_WRONG_TYPE, f"expected a {expected_type} token, got {claims.typ}")
        now = self.now()
        if claims.iat > now + _CLOCK_SKEW_S:
            raise TokenError(TOK_INVALID, "token issued in the future")
        if claims.exp <= now:
            raise TokenError(TOK_EXPIRED, "token expired")
        with self._lock:
            fam = self._families.get(claims.fam)
            if fam is None:
                raise TokenError(TOK_REVOKED, "unknown session (log in again)")
            if fam.revoked:
                raise TokenError(TOK_REVOKED, "session revoked")
            if now >= fam.session_end:
                raise TokenError(TOK_EXPIRED, "session lifetime exceeded")
        return claims

    # ---- internals --------------------------------------------------------------
    def _sign(self, body: str) -> str:
        mac = hmac.new(self._secret, f"{_HEADER_B64}.{body}".encode(), hashlib.sha256).digest()
        return _b64e(mac)

    def _mint(self, typ: str, subject: str, audience: str, scopes: tuple[str, ...], ttl: int,
              family: str, actor: str = "") -> tuple[str, str, int]:
        now = self.now()
        jti = secrets.token_urlsafe(12)
        payload: dict[str, Any] = {"iss": self.ISSUER, "sub": subject, "aud": audience,
                                   "scope": " ".join(scopes), "iat": now, "exp": now + ttl,
                                   "jti": jti, "typ": typ, "fam": family}
        if actor:
            payload["act"] = actor
        body = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
        return f"{_HEADER_B64}.{body}.{self._sign(body)}", jti, now + ttl

    def _parse(self, token: Any) -> Claims:
        bad = lambda why: TokenError(TOK_INVALID, why)          # noqa: E731
        if not isinstance(token, str) or not 10 <= len(token) <= 4096:
            raise bad("malformed token")
        parts = token.split(".")
        if len(parts) != 3:
            raise bad("malformed token")
        header, body, sig = parts
        if header != _HEADER_B64:                                # algorithm is pinned
            raise bad("unexpected token header")
        try:
            sig_bytes = sig.encode("ascii")
        except UnicodeEncodeError:
            raise bad("malformed token") from None
        if not hmac.compare_digest(sig_bytes, self._sign(body).encode("ascii")):   # constant time
            raise bad("bad signature")
        try:
            data = json.loads(_b64d(body))
            sub, aud, scope, jti, typ, fam, iss = (data[k] for k in
                                                   ("sub", "aud", "scope", "jti", "typ", "fam", "iss"))
            iat, exp, act = data["iat"], data["exp"], data.get("act", "")
        except (ValueError, KeyError, TypeError, AttributeError):
            raise bad("malformed claims") from None
        if (iss != self.ISSUER or type(iat) is not int or type(exp) is not int
                or not all(isinstance(x, str) for x in (sub, aud, scope, jti, typ, fam, act))):
            raise bad("malformed claims")
        return Claims(sub, aud, tuple(scope.split()), iat, exp, jti, typ, fam, act)

    @staticmethod
    def _name(value: Any, what: str) -> str:
        if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
            raise ValueError(f"invalid {what}")
        return value

    @staticmethod
    def _scopes(scopes: Iterable[str]) -> tuple[str, ...]:
        out = set()
        for s in scopes:
            if not isinstance(s, str) or not _SCOPE_RE.fullmatch(s):
                raise ValueError(f"invalid scope {s!r}")
            out.add(s)
        return tuple(sorted(out))

    def _prune(self, now: int) -> None:
        """Forget sessions that are over, so memory does not grow forever."""
        for fid in [f for f, fam in self._families.items() if now >= fam.session_end]:
            del self._families[fid]


# --------------------------------------------------------------------------------------
# Shared by all three hooks: "is the token on this request good?"
# --------------------------------------------------------------------------------------
def authenticate(service: TokenService, ctx: Context) -> tuple[Claims | None, Decision | None]:
    """Returns (claims, None) for a good token, or (None, BLOCK decision) explaining why not.
    Every hook calls this itself instead of trusting another hook's result, so the hooks do not
    depend on running order or on shared (racy) state."""
    token = ctx.state.get("auth_token")
    if not token:
        return None, Decision.block(TOK_MISSING, "no access token presented")
    try:
        claims = service.verify(token, expected_type="access")
    except TokenError as exc:
        return None, Decision.block(exc.rule_id, exc.reason)
    # Enforce "short-lived" on the VERIFIER side too, not only at issuance.
    if claims.exp - claims.iat > service.access_ttl:
        return None, Decision.block(TOK_TTL, f"access token lives {claims.exp - claims.iat}s, "
                                             f"maximum is {service.access_ttl}s")
    return claims, None


def make_lifetime_hook(service: TokenService):
    """Hook for t1's HookChain: block requests whose token is missing, forged, expired or revoked."""
    def lifetime_hook(msg: dict[str, Any], ctx: Context) -> Decision:
        _, err = authenticate(service, ctx)
        return err if err is not None else Decision.allow()
    return lifetime_hook
