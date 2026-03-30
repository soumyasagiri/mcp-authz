from __future__ import annotations
import asyncio, json, logging, time, uuid, collections
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from .delegation import DelegationChainValidator, DelegationError
from .policy import ToolPolicyEngine, ToolCall, PolicyDecision
from .baseline import AnomalyDetector, AnomalySignal

logger = logging.getLogger(__name__)


class AuthorizationError(Exception):
    def __init__(self, message, code="AUTHORIZATION_ERROR"):
        super().__init__(message)
        self.code = code


@dataclass
class AuthorizationResult:
    allowed: bool
    tool_name: str
    agent_subject: str
    chain_depth: int
    policy_decision: object = None
    anomaly_signal: object = None
    duration_ms: float = 0.0
    request_id: str = ""

    def to_dict(self):
        return {
            "allowed": self.allowed,
            "tool": self.tool_name,
            "agent": self.agent_subject,
            "chain_depth": self.chain_depth,
            "policy": {
                "allow": self.policy_decision.allow if self.policy_decision else None,
                "reason": self.policy_decision.reason if self.policy_decision else None,
                "rule": self.policy_decision.matched_rule if self.policy_decision else None,
            },
            "anomaly": {
                "score": self.anomaly_signal.score if self.anomaly_signal else 0.0,
                "is_anomalous": self.anomaly_signal.is_anomalous if self.anomaly_signal else False,
            },
            "duration_ms": round(self.duration_ms, 2),
            "request_id": self.request_id,
        }


@dataclass
class AuditEvent:
    timestamp: float
    request_id: str
    decision: str
    tool_name: str
    agent_subject: str
    chain_depth: int
    reason: str
    duration_ms: float
    anomaly_score: float = 0.0


class AuditLog:
    def __init__(self, max_memory_events=10000):
        self._events = collections.deque(maxlen=max_memory_events)
        self._logger = logging.getLogger("mcp_authz.audit")

    def record(self, event: AuditEvent):
        self._events.append(event)
        self._logger.info(json.dumps({
            "ts": event.timestamp,
            "rid": event.request_id,
            "decision": event.decision,
            "tool": event.tool_name,
            "agent": event.agent_subject,
            "depth": event.chain_depth,
            "reason": event.reason,
            "duration_ms": round(event.duration_ms, 2),
            "anomaly_score": event.anomaly_score,
        }))

    def recent(self, n=100):
        return list(self._events)[-n:]


class AuthFailureRateLimiter:
    def __init__(self, max_failures=10, window_seconds=60):
        self._failures: dict[str, list] = {}
        self._max = max_failures
        self._window = window_seconds

    def check_and_record(self, source: str) -> bool:
        now = time.time()
        if source not in self._failures:
            self._failures[source] = []
        self._failures[source] = [t for t in self._failures[source] if now - t < self._window]
        if len(self._failures[source]) >= self._max:
            return False
        self._failures[source].append(now)
        return True

    def record_failure(self, source: str):
        now = time.time()
        if source not in self._failures:
            self._failures[source] = []
        self._failures[source].append(now)


class MCPAuthzProxy:
    def __init__(self, validator, policy_engine, anomaly_detector=None,
                 on_deny=None, on_anomaly=None,
                 audit_log=None, rate_limiter=None):
        self.validator = validator
        self.policy_engine = policy_engine
        self.anomaly_detector = anomaly_detector
        self.on_deny = on_deny
        self.on_anomaly = on_anomaly
        self.audit_log = audit_log or AuditLog()
        self.rate_limiter = rate_limiter or AuthFailureRateLimiter()

    async def authorize(self, token, tool_name, params, mcp_server_id,
                        request_id=None, source_ip="unknown"):
        start = time.perf_counter()
        rid = request_id or str(uuid.uuid4())[:8]

        # Rate limit check before expensive JWT validation
        if not self.rate_limiter.check_and_record(source_ip):
            dur = (time.perf_counter() - start) * 1000
            self.audit_log.record(AuditEvent(
                timestamp=time.time(), request_id=rid, decision="RATE_LIMITED",
                tool_name=tool_name, agent_subject="unknown", chain_depth=0,
                reason=f"Too many auth failures from {source_ip}", duration_ms=dur,
            ))
            raise AuthorizationError(
                f"Rate limit exceeded for source {source_ip}", code="RATE_LIMITED"
            )

        try:
            chain = self.validator.validate(token)
        except Exception as e:
            dur = (time.perf_counter() - start) * 1000
            self.rate_limiter.record_failure(source_ip)
            r = AuthorizationResult(
                allowed=False, tool_name=tool_name, agent_subject="unknown",
                chain_depth=0, duration_ms=dur, request_id=rid,
            )
            self.audit_log.record(AuditEvent(
                timestamp=time.time(), request_id=rid, decision="DENY",
                tool_name=tool_name, agent_subject="unknown", chain_depth=0,
                reason=f"INVALID_DELEGATION_CHAIN: {e}", duration_ms=dur,
            ))
            logger.warning(f"[{rid}] DENIED tool={tool_name} chain_error={e}")
            if self.on_deny:
                self.on_deny(r)
            raise AuthorizationError(str(e), code="INVALID_DELEGATION_CHAIN")

        call = ToolCall(tool_name=tool_name, params=params,
                        mcp_server_id=mcp_server_id, request_id=rid)
        decision = self.policy_engine.evaluate(call, chain)

        if not decision.allow:
            dur = (time.perf_counter() - start) * 1000
            r = AuthorizationResult(
                allowed=False, tool_name=tool_name, agent_subject=chain.current_actor,
                chain_depth=chain.depth, policy_decision=decision,
                duration_ms=dur, request_id=rid,
            )
            self.audit_log.record(AuditEvent(
                timestamp=time.time(), request_id=rid, decision="DENY",
                tool_name=tool_name, agent_subject=chain.current_actor,
                chain_depth=chain.depth, reason=f"POLICY_DENIED: {decision.reason}",
                duration_ms=dur,
            ))
            logger.warning(f"[{rid}] DENIED tool={tool_name} agent={chain.current_actor} reason={decision.reason}")
            if self.on_deny:
                self.on_deny(r)
            raise AuthorizationError(decision.reason, code="POLICY_DENIED")

        sig = None
        if self.anomaly_detector:
            sig = self.anomaly_detector.observe_and_evaluate(
                agent_subject=chain.current_actor, tool_name=tool_name, params=params
            )
            if self.on_anomaly and sig.is_anomalous:
                self.on_anomaly(sig)
            if sig.should_block:
                dur = (time.perf_counter() - start) * 1000
                r = AuthorizationResult(
                    allowed=False, tool_name=tool_name, agent_subject=chain.current_actor,
                    chain_depth=chain.depth, policy_decision=decision,
                    anomaly_signal=sig, duration_ms=dur, request_id=rid,
                )
                self.audit_log.record(AuditEvent(
                    timestamp=time.time(), request_id=rid, decision="DENY",
                    tool_name=tool_name, agent_subject=chain.current_actor,
                    chain_depth=chain.depth,
                    reason=f"ANOMALY_BLOCKED: score={sig.score}",
                    duration_ms=dur, anomaly_score=sig.score,
                ))
                logger.warning(f"[{rid}] BLOCKED tool={tool_name} score={sig.score}")
                if self.on_deny:
                    self.on_deny(r)
                raise AuthorizationError(
                    f"Anomaly detected (score={sig.score})", code="ANOMALY_BLOCKED"
                )

        dur = (time.perf_counter() - start) * 1000
        self.audit_log.record(AuditEvent(
            timestamp=time.time(), request_id=rid, decision="ALLOW",
            tool_name=tool_name, agent_subject=chain.current_actor,
            chain_depth=chain.depth, reason="all_layers_passed",
            duration_ms=dur, anomaly_score=sig.score if sig else 0.0,
        ))
        logger.debug(f"[{rid}] ALLOWED tool={tool_name} agent={chain.current_actor} {dur:.1f}ms")
        return AuthorizationResult(
            allowed=True, tool_name=tool_name, agent_subject=chain.current_actor,
            chain_depth=chain.depth, policy_decision=decision,
            anomaly_signal=sig, duration_ms=dur, request_id=rid,
        )


async def run_proxy_server(proxy, upstream_url, host="0.0.0.0", port=9000):
    from aiohttp import web, ClientSession, ClientTimeout

    async def handle(request):
        try:
            body = await request.json()
        except Exception:
            return web.Response(status=400, text=json.dumps({"error": "bad json"}),
                                content_type="application/json")

        method = body.get("method", "")
        rid = body.get("id")
        source_ip = request.headers.get("X-Forwarded-For", request.remote or "unknown")

        if method == "tools/call":
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            if not token:
                return _err(rid, -32600, "Missing Authorization header", "NO_TOKEN")
            p = body.get("params", {})
            try:
                await proxy.authorize(
                    token=token, tool_name=p.get("name", ""),
                    params=p.get("arguments", {}), mcp_server_id=upstream_url,
                    request_id=str(rid), source_ip=source_ip,
                )
            except AuthorizationError as e:
                return _err(rid, -32603, str(e), e.code)

        async with ClientSession(timeout=ClientTimeout(total=30)) as s:
            try:
                async with s.post(upstream_url, json=body,
                                  headers=dict(request.headers)) as resp:
                    return web.Response(status=resp.status,
                                        text=await resp.text(),
                                        content_type="application/json")
            except Exception as e:
                return _err(rid, -32603, f"Upstream error: {e}", "UPSTREAM_ERROR")

    def _err(rid, code, msg, data):
        return web.Response(
            status=200,
            text=json.dumps({"jsonrpc": "2.0", "id": rid,
                             "error": {"code": code, "message": msg, "data": data}}),
            content_type="application/json",
        )

    async def health(r):
        return web.Response(text=json.dumps({"status": "ok"}),
                            content_type="application/json")

    async def audit_endpoint(r):
        n = int(r.rel_url.query.get("n", 100))
        events = proxy.audit_log.recent(n)
        return web.Response(
            text=json.dumps([e.__dict__ for e in events], default=str),
            content_type="application/json",
        )

    app = web.Application()
    app.router.add_post("/", handle)
    app.router.add_post("/mcp", handle)
    app.router.add_get("/health", health)
    app.router.add_get("/audit", audit_endpoint)

    logger.info(f"mcp-authz proxy on {host}:{port} -> {upstream_url}")
    logger.info(f"Audit log endpoint: http://{host}:{port}/audit")
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, host, port).start()
    await asyncio.Event().wait()
