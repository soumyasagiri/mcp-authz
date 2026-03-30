
from __future__ import annotations
import asyncio, json, logging, time, uuid
from dataclasses import dataclass
from .delegation import DelegationChainValidator, DelegationError
from .policy import ToolPolicyEngine, ToolCall, PolicyDecision
from .baseline import AnomalyDetector, AnomalySignal
logger = logging.getLogger(__name__)
class AuthorizationError(Exception):
    def __init__(self, message, code="AUTHORIZATION_ERROR"):
        super().__init__(message); self.code=code
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
        return {"allowed":self.allowed,"tool":self.tool_name,"agent":self.agent_subject,"policy":{"allow":self.policy_decision.allow if self.policy_decision else None,"reason":self.policy_decision.reason if self.policy_decision else None},"anomaly":{"score":self.anomaly_signal.score if self.anomaly_signal else 0.0},"duration_ms":round(self.duration_ms,2)}
class MCPAuthzProxy:
    def __init__(self, validator, policy_engine, anomaly_detector=None, on_deny=None, on_anomaly=None):
        self.validator=validator; self.policy_engine=policy_engine
        self.anomaly_detector=anomaly_detector; self.on_deny=on_deny; self.on_anomaly=on_anomaly
    async def authorize(self, token, tool_name, params, mcp_server_id, request_id=None):
        start=time.perf_counter(); rid=request_id or str(uuid.uuid4())[:8]
        try:
            chain=self.validator.validate(token)
        except DelegationError as e:
            dur=(time.perf_counter()-start)*1000
            r=AuthorizationResult(allowed=False,tool_name=tool_name,agent_subject="unknown",chain_depth=0,duration_ms=dur,request_id=rid)
            logger.warning(f"[{rid}] DENIED tool={tool_name} error={e}")
            if self.on_deny: self.on_deny(r)
            raise AuthorizationError(str(e),code="INVALID_DELEGATION_CHAIN")
        call=ToolCall(tool_name=tool_name,params=params,mcp_server_id=mcp_server_id,request_id=rid)
        decision=self.policy_engine.evaluate(call,chain)
        if not decision.allow:
            dur=(time.perf_counter()-start)*1000
            r=AuthorizationResult(allowed=False,tool_name=tool_name,agent_subject=chain.current_actor,chain_depth=chain.depth,policy_decision=decision,duration_ms=dur,request_id=rid)
            logger.warning(f"[{rid}] DENIED tool={tool_name} reason={decision.reason}")
            if self.on_deny: self.on_deny(r)
            raise AuthorizationError(decision.reason,code="POLICY_DENIED")
        sig=None
        if self.anomaly_detector:
            sig=self.anomaly_detector.observe_and_evaluate(agent_subject=chain.current_actor,tool_name=tool_name,params=params)
            if self.on_anomaly and sig.is_anomalous: self.on_anomaly(sig)
            if sig.should_block:
                dur=(time.perf_counter()-start)*1000
                r=AuthorizationResult(allowed=False,tool_name=tool_name,agent_subject=chain.current_actor,chain_depth=chain.depth,policy_decision=decision,anomaly_signal=sig,duration_ms=dur,request_id=rid)
                logger.warning(f"[{rid}] BLOCKED tool={tool_name} score={sig.score}")
                if self.on_deny: self.on_deny(r)
                raise AuthorizationError(f"Anomaly detected score={sig.score}",code="ANOMALY_BLOCKED")
        dur=(time.perf_counter()-start)*1000
        return AuthorizationResult(allowed=True,tool_name=tool_name,agent_subject=chain.current_actor,chain_depth=chain.depth,policy_decision=decision,anomaly_signal=sig,duration_ms=dur,request_id=rid)
async def run_proxy_server(proxy, upstream_url, host="0.0.0.0", port=9000):
    from aiohttp import web, ClientSession, ClientTimeout
    async def handle(request):
        try: body=await request.json()
        except: return web.Response(status=400,text='{"error":"bad json"}',content_type="application/json")
        method=body.get("method",""); rid=body.get("id")
        if method=="tools/call":
            token=request.headers.get("Authorization","").replace("Bearer ","")
            if not token: return err(rid,-32600,"Missing Authorization","NO_TOKEN")
            p=body.get("params",{})
            try:
                await proxy.authorize(token=token,tool_name=p.get("name",""),params=p.get("arguments",{}),mcp_server_id=upstream_url,request_id=str(rid))
            except AuthorizationError as e:
                return err(rid,-32603,str(e),e.code)
        async with ClientSession(timeout=ClientTimeout(total=30)) as s:
            try:
                async with s.post(upstream_url,json=body,headers=dict(request.headers)) as resp:
                    return web.Response(status=resp.status,text=await resp.text(),content_type="application/json")
            except Exception as e:
                return err(rid,-32603,f"Upstream: {e}","UPSTREAM_ERROR")
    def err(rid,code,msg,data):
        return web.Response(status=200,text=json.dumps({"jsonrpc":"2.0","id":rid,"error":{"code":code,"message":msg,"data":data}}),content_type="application/json")
    async def health(r): return web.Response(text='{"status":"ok"}',content_type="application/json")
    app=web.Application()
    app.router.add_post("/",handle); app.router.add_post("/mcp",handle); app.router.add_get("/health",health)
    logger.info(f"Proxy on {host}:{port} -> {upstream_url}")
    runner=web.AppRunner(app); await runner.setup()
    await web.TCPSite(runner,host,port).start()
    await asyncio.Event().wait()
