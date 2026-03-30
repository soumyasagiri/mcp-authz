
from __future__ import annotations
import logging, time
from dataclasses import dataclass
import urllib.request, urllib.error, json as _json
logger = logging.getLogger(__name__)
class PolicyEngineError(Exception): pass
@dataclass
class ToolCall:
    tool_name: str
    params: dict
    mcp_server_id: str
    request_id: str = None
@dataclass
class PolicyDecision:
    allow: bool
    reason: str
    policy_version: str = "unknown"
    evaluated_at: float = 0.0
    matched_rule: str = None
    def __post_init__(self):
        if not self.evaluated_at: self.evaluated_at = time.time()
BLOCKED = {"shell_execute","code_execute","eval","system_call","exec","run_command","delete_account","transfer_funds","export_all_data"}
class ToolPolicyEngine:
    def __init__(self, opa_url=None, default_deny=True, timeout_seconds=1.0):
        self.opa_url=opa_url; self.default_deny=default_deny; self.timeout_seconds=timeout_seconds
    def evaluate(self, tool_call, chain):
        inp=self._build_input(tool_call,chain)
        if self.opa_url: return self._evaluate_opa(inp)
        return self._evaluate_local(inp)
    def _evaluate_opa(self, inp):
        try:
            data = _json.dumps({"input": inp}).encode()
                req = urllib.request.Request(
                    f"{self.opa_url}/v1/data/mcp/authz",
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                    resp_body = resp.read()
                    resp = type("R", (), {"json": lambda self: _json.loads(resp_body), "status_code": 200})()
            data=resp.json().get("result",{})
            return PolicyDecision(allow=bool(data.get("allow",False)),reason=data.get("reason","denied"),policy_version="opa",matched_rule=data.get("matched_rule"))
        except Exception as e:
            return PolicyDecision(allow=not self.default_deny,reason=str(e),policy_version="fallback",matched_rule="opa_error")
    def _evaluate_local(self, inp):
        name=inp["tool"]["name"]; pt=inp["agent"]["principal_type"]
        scopes=set(inp["agent"]["effective_scopes"]); depth=inp["chain"]["depth"]
        if name in BLOCKED:
            return PolicyDecision(allow=False,reason=f"Tool '{name}' is blocked",matched_rule="blocked_tools",policy_version="built-in")
        if pt=="service_agent":
            allowed={"health_check","metrics_read","status_check","list_resources","read_resource","ping"}
            prefix=name.split("_")[0] if "_" in name else name
            if not any(s.startswith(prefix) or s=="*" for s in scopes) and name not in allowed:
                return PolicyDecision(allow=False,reason=f"Service agent lacks scope for '{name}'",matched_rule="service_scope",policy_version="built-in")
        if pt=="human_delegated_agent":
            if not scopes:
                return PolicyDecision(allow=False,reason="No effective scopes",matched_rule="empty_scopes",policy_version="built-in")
            prefix=name.split("_")[0] if "_" in name else name
            if not any(s.startswith(prefix) or s=="*" or ":" in s for s in scopes):
                return PolicyDecision(allow=False,reason=f"No scope covers '{name}'",matched_rule="scope_check",policy_version="built-in")
        if pt=="orchestrator_agent" and depth>3:
            return PolicyDecision(allow=False,reason=f"Depth {depth} exceeds max",matched_rule="depth_check",policy_version="built-in")
        return PolicyDecision(allow=True,reason="allowed",matched_rule="default_allow",policy_version="built-in")
    def _build_input(self, tool_call, chain):
        actor=chain.links[-1] if chain.links else None
        return {
            "tool":{"name":tool_call.tool_name,"params":tool_call.params,"server_id":tool_call.mcp_server_id},
            "agent":{"subject":chain.current_actor,"root_principal":chain.root_principal,"principal_type":actor.principal_type if actor else "unknown","effective_scopes":chain.effective_scopes,"is_human_delegated":chain.is_human_delegated},
            "chain":{"depth":chain.depth,"is_human_delegated":chain.is_human_delegated,"is_service_agent":chain.is_service_agent},
        }
