from __future__ import annotations
import logging, time, json, urllib.request, urllib.error
from dataclasses import dataclass

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
    policy_version: str = "built-in-v1"
    evaluated_at: float = 0.0
    matched_rule: str = None

BLOCKED_TOOLS = {
    "transfer_funds", "code_execute", "eval", "exec",
    "export_all_data", "delete_account", "shell_execute",
    "system_call", "run_command",
}

TOOL_SCOPE_MAP = {
    "account": ["account:read", "account:write", "account:admin"],
    "transaction": ["transaction:read", "transaction:write"],
    "transfer": ["transfer:execute"],
    "metrics": ["metrics:read"],
    "search": ["search:read"],
    "report": ["report:read"],
}

class ToolPolicyEngine:
    def __init__(self, opa_url=None, default_deny=True,
                 blocked_tools=None, timeout_seconds=2):
        self.opa_url = opa_url
        self.default_deny = default_deny
        self.blocked_tools = blocked_tools or BLOCKED_TOOLS
        self.timeout_seconds = timeout_seconds

    def evaluate(self, call, chain) -> PolicyDecision:
        t = time.time()

        if call.tool_name in self.blocked_tools:
            return PolicyDecision(
                allow=False,
                reason=f"Tool '{call.tool_name}' is on the permanent block list",
                matched_rule="permanent_block",
                evaluated_at=t,
            )

        if self.opa_url:
            try:
                return self._evaluate_opa(call, chain, t)
            except Exception as e:
                logger.warning(f"OPA evaluation failed, falling back to built-in: {e}")

        return self._evaluate_builtin(call, chain, t)

    def _evaluate_builtin(self, call, chain, t) -> PolicyDecision:
        if not chain.effective_scopes:
            return PolicyDecision(
                allow=False,
                reason="Agent has no effective scopes",
                matched_rule="no_scopes",
                evaluated_at=t,
            )

        prefix = call.tool_name.split("_")[0]
        covered = any(
            scope.startswith(prefix) or scope.split(":")[0] == prefix
            for scope in chain.effective_scopes
        )

        if not covered and self.default_deny:
            return PolicyDecision(
                allow=False,
                reason=f"No scope covers tool '{call.tool_name}'",
                matched_rule="scope_coverage",
                evaluated_at=t,
            )

        return PolicyDecision(
            allow=True,
            reason="built-in policy allows",
            matched_rule="allow",
            evaluated_at=t,
        )

    def _evaluate_opa(self, call, chain, t) -> PolicyDecision:
        inp = {
            "tool": {
                "name": call.tool_name,
                "params": call.params,
                "server_id": call.mcp_server_id,
            },
            "agent": {
                "subject": chain.current_actor,
                "root_principal": chain.root_principal,
                "principal_type": chain.links[-1].principal_type if chain.links else "unknown",
                "effective_scopes": chain.effective_scopes,
                "is_human_delegated": chain.is_human_delegated,
            },
            "chain": {
                "depth": chain.depth,
            },
        }

        data = json.dumps({"input": inp}).encode()
        req = urllib.request.Request(
            f"{self.opa_url}/v1/data/mcp/authz",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                result = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            raise PolicyEngineError(f"OPA returned {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            raise PolicyEngineError(f"OPA unreachable: {e.reason}")

        allowed = result.get("result", {}).get("allow", False)
        reason = result.get("result", {}).get("reason", "opa_decision")

        return PolicyDecision(
            allow=bool(allowed),
            reason=reason,
            policy_version="opa",
            matched_rule="opa_policy",
            evaluated_at=t,
        )
