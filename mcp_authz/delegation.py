from __future__ import annotations
import json, time, logging
from dataclasses import dataclass, field
from typing import Optional
import jwt

logger = logging.getLogger(__name__)

class DelegationError(Exception): pass
class AttenuationViolation(DelegationError): pass
class TokenExpiredError(DelegationError): pass
class ReplayAttackError(DelegationError): pass


class JtiStore:
    def __init__(self, max_size=100000):
        self._seen = {}
        self._max_size = max_size
        self._last_cleanup = time.time()

    def check_and_add(self, jti, expires_at):
        now = time.time()
        if now - self._last_cleanup > 300:
            self._seen = {k: v for k, v in self._seen.items() if v > now}
            self._last_cleanup = now
        if jti in self._seen:
            return False
        if len(self._seen) >= self._max_size:
            self._seen = {k: v for k, v in self._seen.items() if v > now}
        self._seen[jti] = expires_at
        return True


class JwksCache:
    def __init__(self, ttl_seconds=300):
        self._cache = {}
        self._ttl = ttl_seconds

    def get(self, key):
        if key in self._cache:
            value, expires = self._cache[key]
            if time.time() < expires:
                return value
            del self._cache[key]
        return None

    def set(self, key, value):
        self._cache[key] = (value, time.time() + self._ttl)

    def invalidate(self, key):
        self._cache.pop(key, None)


@dataclass
class DelegationLink:
    subject: str
    principal_type: str
    scopes: list
    issued_at: int
    expires_at: int
    issuer: str
    audience: list
    jti: str = ""
    raw_claims: dict = field(default_factory=dict)


@dataclass
class DelegationChain:
    links: list
    depth: int
    root_principal: str
    current_actor: str
    effective_scopes: list
    valid: bool = True

    @property
    def is_human_delegated(self):
        return self.links[0].principal_type == "human"

    @property
    def is_service_agent(self):
        return len(self.links) == 1 and self.links[0].principal_type == "service_agent"


class DelegationChainValidator:
    def __init__(self, jwks_uri=None, public_key=None, max_delegation_depth=3,
                 clock_skew_seconds=30, jwks_ttl_seconds=300,
                 enable_replay_protection=True, allowed_issuers=None):
        if not jwks_uri and not public_key:
            raise ValueError("Provide either jwks_uri or public_key")
        self.jwks_uri = jwks_uri
        self.public_key = public_key
        self.max_delegation_depth = max_delegation_depth
        self.clock_skew_seconds = clock_skew_seconds
        self.enable_replay_protection = enable_replay_protection
        self.allowed_issuers = allowed_issuers
        self._jwks_cache = JwksCache(ttl_seconds=jwks_ttl_seconds)
        self._jti_store = JtiStore()

    def validate(self, token):
        claims = self._decode_token(token)
        links = self._parse_chain(claims)
        self._enforce_depth(links)
        self._enforce_attenuation(links)
        self._enforce_expiry(links)
        if self.allowed_issuers:
            self._enforce_issuers(links)
        if self.enable_replay_protection:
            self._enforce_no_replay(links)
        return DelegationChain(
            links=links, depth=len(links),
            root_principal=links[0].subject,
            current_actor=links[-1].subject,
            effective_scopes=self._compute_effective_scopes(links),
        )

    def _decode_token(self, token):
        header = jwt.get_unverified_header(token)
        key = self.public_key if self.public_key else self._fetch_jwks_key(header.get("kid"))
        try:
            return jwt.decode(token, key, algorithms=["RS256","ES256"], options={"verify_exp": False})
        except jwt.InvalidTokenError as e:
            raise DelegationError(f"JWT validation failed: {e}") from e

    def _fetch_jwks_key(self, kid):
        import urllib.request
        cache_key = f"{self.jwks_uri}:{kid}"
        cached = self._jwks_cache.get(cache_key)
        if cached:
            return cached
        try:
            with urllib.request.urlopen(self.jwks_uri, timeout=5) as resp:
                jwks = json.loads(resp.read())
        except Exception as e:
            raise DelegationError(f"Failed to fetch JWKS: {e}") from e
        for k in jwks.get("keys", []):
            if kid is None or k.get("kid") == kid:
                key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(k))
                self._jwks_cache.set(cache_key, key)
                return key
        raise DelegationError(f"Key kid={kid!r} not found in JWKS")

    def _parse_chain(self, claims):
        links = []
        current = claims
        while current:
            has_act = bool(current.get("act"))
            sub = current.get("sub", "unknown")
            pt = current.get("principal_type") or (
                "human" if not has_act and ("@" in sub or sub.startswith("user:"))
                else ("service_agent" if not has_act else "human_delegated_agent")
            )
            scope = current.get("scope", "")
            scopes = scope if isinstance(scope, list) else [s.strip() for s in scope.split() if s.strip()]
            aud = current.get("aud", [])
            links.append(DelegationLink(
                subject=sub, principal_type=pt, scopes=scopes,
                issued_at=current.get("iat", 0), expires_at=current.get("exp", 0),
                issuer=current.get("iss", ""),
                audience=[aud] if isinstance(aud, str) else aud,
                jti=current.get("jti", ""),
                raw_claims=dict(current),
            ))
            current = current.get("act")
        links.reverse()
        return links

    def _enforce_depth(self, links):
        if len(links) > self.max_delegation_depth:
            raise DelegationError(f"Chain depth {len(links)} exceeds max {self.max_delegation_depth}")

    def _enforce_attenuation(self, links):
        for i in range(1, len(links)):
            amplified = set(links[i].scopes) - set(links[i-1].scopes)
            if amplified:
                raise AttenuationViolation(
                    f"Agent {links[i].subject!r} claims {amplified} not granted by {links[i-1].subject!r}"
                )

    def _enforce_expiry(self, links):
        now = int(time.time())
        for link in links:
            if link.expires_at and (link.expires_at + self.clock_skew_seconds) < now:
                raise TokenExpiredError(f"Token for {link.subject!r} expired at {link.expires_at}")

    def _enforce_issuers(self, links):
        for link in links:
            if link.issuer and link.issuer not in self.allowed_issuers:
                raise DelegationError(f"Issuer {link.issuer!r} not trusted")

    def _enforce_no_replay(self, links):
        for link in links:
            if not link.jti:
                continue
            if not self._jti_store.check_and_add(link.jti, link.expires_at):
                raise ReplayAttackError(
                    f"Replay attack detected: jti={link.jti!r} for {link.subject!r} already seen"
                )

    def _compute_effective_scopes(self, links):
        if not links:
            return []
        effective = set(links[0].scopes)
        for link in links[1:]:
            effective &= set(link.scopes)
        return sorted(effective)
