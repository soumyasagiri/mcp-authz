import pytest, time, jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from mcp_authz import (
    DelegationChainValidator, DelegationChain, AttenuationViolation,
    TokenExpiredError, ReplayAttackError,
    ToolPolicyEngine, ToolCall, PolicyDecision,
    AnomalyDetector, AnomalySignal,
    MCPAuthzProxy, AuthorizationError, AuditLog, AuthFailureRateLimiter,
)


def make_keypair():
    key = rsa.generate_private_key(65537, 2048, default_backend())
    priv = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


def make_token(private_key, claims):
    return jwt.encode(claims, private_key, algorithm="RS256")


def future(s=3600):
    return int(time.time()) + s


PRIV, PUB = make_keypair()


def valid_claims(scopes="account:read", sub="agent:test", jti=None):
    c = {
        "sub": sub, "principal_type": "human_delegated_agent",
        "scope": scopes, "iss": "https://auth.test", "exp": future(), "iat": int(time.time()),
        "act": {"sub": "user:alice@example.com", "principal_type": "human",
                "scope": scopes, "exp": future(), "iat": int(time.time())},
    }
    if jti:
        c["jti"] = jti
    return c


def validator(replay=True):
    return DelegationChainValidator(public_key=PUB, enable_replay_protection=replay)


class TestDelegationChainValidator:
    def test_valid_chain_passes(self):
        token = make_token(PRIV, valid_claims())
        chain = validator(replay=False).validate(token)
        assert chain.current_actor == "agent:test"
        assert chain.root_principal == "user:alice@example.com"
        assert chain.depth == 2

    def test_attenuation_violation_caught(self):
        claims = valid_claims("account:read")
        claims["scope"] = "account:read account:admin"
        token = make_token(PRIV, claims)
        with pytest.raises(AttenuationViolation):
            validator(replay=False).validate(token)

    def test_expired_token_rejected(self):
        claims = valid_claims()
        claims["exp"] = int(time.time()) - 7200
        claims["act"]["exp"] = int(time.time()) - 7200
        token = make_token(PRIV, claims)
        with pytest.raises(TokenExpiredError):
            validator(replay=False).validate(token)

    def test_depth_exceeded_rejected(self):
        v = DelegationChainValidator(public_key=PUB, max_delegation_depth=1, enable_replay_protection=False)
        token = make_token(PRIV, valid_claims())
        with pytest.raises(Exception, match="depth"):
            v.validate(token)

    def test_replay_attack_blocked(self):
        v = validator(replay=True)
        claims = valid_claims(jti="unique-jti-123")
        token = make_token(PRIV, claims)
        v.validate(token)
        with pytest.raises(ReplayAttackError):
            v.validate(token)

    def test_replay_no_jti_allowed(self):
        v = validator(replay=True)
        token = make_token(PRIV, valid_claims())
        v.validate(token)
        v.validate(token)

    def test_effective_scopes_intersection(self):
        claims = valid_claims("account:read")
        token = make_token(PRIV, claims)
        chain = validator(replay=False).validate(token)
        assert "account:read" in chain.effective_scopes
        assert "transaction:read" not in chain.effective_scopes

    def test_service_agent_no_act(self):
        claims = {"sub": "service:worker", "principal_type": "service_agent",
                  "scope": "metrics:read", "exp": future(), "iat": int(time.time())}
        token = make_token(PRIV, claims)
        chain = validator(replay=False).validate(token)
        assert chain.is_service_agent


class TestPolicyEngine:
    def make_chain(self, scopes="account:read"):
        token = make_token(PRIV, valid_claims(scopes))
        return validator(replay=False).validate(token)

    def test_allowed_tool_passes(self):
        engine = ToolPolicyEngine(default_deny=True)
        call = ToolCall(tool_name="account_balance", params={}, mcp_server_id="test")
        chain = self.make_chain("account:read")
        decision = engine.evaluate(call, chain)
        assert decision.allow

    def test_blocked_tool_denied(self):
        engine = ToolPolicyEngine(default_deny=True)
        for tool in ["transfer_funds", "code_execute", "export_all_data", "eval"]:
            call = ToolCall(tool_name=tool, params={}, mcp_server_id="test")
            chain = self.make_chain("account:read transfer:execute")
            decision = engine.evaluate(call, chain)
            assert not decision.allow, f"{tool} should be blocked"

    def test_no_scopes_denied(self):
        engine = ToolPolicyEngine(default_deny=True)
        call = ToolCall(tool_name="account_balance", params={}, mcp_server_id="test")
        claims = valid_claims("")
        claims["scope"] = ""
        claims["act"]["scope"] = ""
        token = make_token(PRIV, claims)
        chain = validator(replay=False).validate(token)
        decision = engine.evaluate(call, chain)
        assert not decision.allow


class TestAnomalyDetector:
    def test_first_call_not_blocked(self):
        d = AnomalyDetector(observe_only_during_warmup=True)
        sig = d.observe_and_evaluate("agent:x", "account_balance", {"id": "1"})
        assert not sig.should_block

    def test_normal_repeated_calls_low_score(self):
        d = AnomalyDetector()
        for _ in range(20):
            sig = d.observe_and_evaluate("agent:x", "account_balance", {"id": "1"})
        assert sig.score < 0.5

    def test_baseline_reset_clears_history(self):
        d = AnomalyDetector()
        for _ in range(30):
            d.observe_and_evaluate("agent:x", "account_balance", {"id": "1"})
        d.reset_baseline("agent:x")
        sig = d.observe_and_evaluate("agent:x", "account_balance", {"id": "1"})
        assert sig.score < 0.5


class TestMCPAuthzProxy:
    def make_proxy(self):
        v = DelegationChainValidator(public_key=PUB, enable_replay_protection=False)
        p = ToolPolicyEngine(default_deny=True)
        a = AnomalyDetector()
        return MCPAuthzProxy(validator=v, policy_engine=p, anomaly_detector=a)

    @pytest.mark.asyncio
    async def test_authorized_call_passes(self):
        proxy = self.make_proxy()
        token = make_token(PRIV, valid_claims("account:read"))
        result = await proxy.authorize(token, "account_balance", {"id": "1"}, "test")
        assert result.allowed

    @pytest.mark.asyncio
    async def test_blocked_tool_raises(self):
        proxy = self.make_proxy()
        token = make_token(PRIV, valid_claims("transfer:execute"))
        with pytest.raises(AuthorizationError) as exc:
            await proxy.authorize(token, "transfer_funds", {"amount": 100}, "test")
        assert exc.value.code == "POLICY_DENIED"

    @pytest.mark.asyncio
    async def test_invalid_token_raises(self):
        proxy = self.make_proxy()
        with pytest.raises(AuthorizationError) as exc:
            await proxy.authorize("bad.token.here", "account_balance", {}, "test")
        assert exc.value.code == "INVALID_DELEGATION_CHAIN"

    @pytest.mark.asyncio
    async def test_audit_log_records_deny(self):
        proxy = self.make_proxy()
        token = make_token(PRIV, valid_claims("account:read"))
        try:
            await proxy.authorize(token, "transfer_funds", {}, "test")
        except AuthorizationError:
            pass
        events = proxy.audit_log.recent(10)
        assert any(e.decision == "DENY" for e in events)

    @pytest.mark.asyncio
    async def test_audit_log_records_allow(self):
        proxy = self.make_proxy()
        token = make_token(PRIV, valid_claims("account:read"))
        await proxy.authorize(token, "account_balance", {"id": "1"}, "test")
        events = proxy.audit_log.recent(10)
        assert any(e.decision == "ALLOW" for e in events)

    @pytest.mark.asyncio
    async def test_rate_limiter_blocks_after_threshold(self):
        proxy = self.make_proxy()
        limiter = AuthFailureRateLimiter(max_failures=3, window_seconds=60)
        proxy.rate_limiter = limiter
        for _ in range(3):
            limiter.record_failure("10.0.0.1")
        with pytest.raises(AuthorizationError) as exc:
            token = make_token(PRIV, valid_claims())
            await proxy.authorize(token, "account_balance", {}, "test", source_ip="10.0.0.1")
        assert exc.value.code == "RATE_LIMITED"

    def test_result_to_dict(self):
        from mcp_authz import AuthorizationResult
        r = AuthorizationResult(allowed=True, tool_name="test", agent_subject="agent:x",
                                chain_depth=2, request_id="abc123")
        d = r.to_dict()
        assert d["allowed"] is True
        assert d["tool"] == "test"
