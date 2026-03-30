# mcp-authz

**Runtime authorization middleware for MCP tool calls.**

Your MCP agent can call any tool it has access to with any parameters and there is nothing between intent and execution. **mcp-authz fixes that.**

```
MCP Client  ──►  [ mcp-authz proxy ]  ──►  MCP Server
                       │
                       ├── Layer 1: Delegation chain (RFC 8693)
                       ├── Layer 2: Tool policy (OPA / built-in)
                       └── Layer 3: Behavioral anomaly detection
```

Zero changes to your MCP client or MCP server.

---

## Run the demo in 60 seconds

Requires Docker Desktop only. No accounts, no API keys.

```bash
git clone https://github.com/YOUR_USERNAME/mcp-authz.git
cd mcp-authz
docker compose -f docker/docker-compose.demo.yml up --build
```

Watch the `agent` container logs. You will see four scenarios run automatically showing each enforcement layer in action.

---

## What it enforces

**Layer 1: Delegation chain integrity (RFC 8693)**

Every agent token must contain an `act` claim chain tracing back to an authorized human or service. The attenuation invariant is cryptographically enforced: scopes at each delegation level must be a subset of the level above. An agent cannot claim permissions not granted by its delegating principal.

```
user:alice  grants  account:read
    └── agent:assistant  claims  account:read   ✓  allowed
        └── agent:sub    claims  account:admin  ✗  BLOCKED: AttenuationViolation
```

**Layer 2: Per-tool authorization policy**

Every tool invocation is evaluated before it reaches the MCP server. Default blocked tools include `shell_execute`, `code_execute`, `eval`, `transfer_funds`, `delete_account`. Custom policies written in Rego (OPA) or evaluated by the built-in engine with no OPA required.

**Layer 3: Behavioral anomaly detection**

Per-agent rolling baseline. Z-score frequency anomaly plus Jaccard parameter structure comparison. Catches compromised credentials doing bulk enumeration even when each individual call is technically authorized.

---

## Quickstart: Library mode

```python
from mcp_authz import MCPAuthzProxy, DelegationChainValidator, ToolPolicyEngine, AnomalyDetector

proxy = MCPAuthzProxy(
    validator=DelegationChainValidator(
        jwks_uri="https://auth.example.com/.well-known/jwks.json"
    ),
    policy_engine=ToolPolicyEngine(),
    anomaly_detector=AnomalyDetector(),
)

try:
    result = await proxy.authorize(
        token=agent_jwt,
        tool_name="orders_search",
        params={"seller_id": "12345"},
        mcp_server_id="orders-mcp",
    )
except AuthorizationError as e:
    print(e.code, str(e))
```

## Quickstart: Proxy server mode

```bash
export UPSTREAM_MCP_URL=http://your-mcp-server:8080
export JWKS_URI=https://auth.example.com/.well-known/jwks.json
docker compose up
```

---

## Principal types

| Type | Description | Token |
|------|-------------|-------|
| `human_delegated_agent` | Agent acting on behalf of a human | JWT with `act` chain, root is human |
| `service_agent` | Autonomous machine-to-machine | JWT with no `act` claim |
| `orchestrator_agent` | Agent that spawns sub-agents | JWT with `act` chain, depth-limited |

---

## Demo scenarios

The demo runs a fictional financial assistant against a live MCP server with seven tools across three risk tiers.

| Scenario | Layer | What happens |
|----------|-------|-------------|
| Normal calls | All three | `account_balance`, `transaction_list`, `transaction_summary` pass |
| Blocked tools | Policy | `transfer_funds`, `code_execute`, `export_all_data` denied before reaching server |
| Attenuation violation | Delegation | Sub-agent claiming `account:admin` not granted by human is rejected cryptographically |
| Credential abuse | Anomaly | 60x bulk `account_search` calls flagged after baseline divergence |

---

## Project structure

```
mcp-authz/
├── mcp_authz/
│   ├── delegation.py      RFC 8693 chain validator
│   ├── policy.py          OPA + built-in policy engine
│   ├── baseline.py        Behavioral anomaly detector
│   ├── proxy.py           MCPAuthzProxy + HTTP proxy server
│   └── server.py          Standalone server entrypoint
├── policies/
│   └── reference/
│       └── universal.rego Rego policies for all three principal types
├── demo/
│   ├── agent/agent.py         Demo agent (four scenarios)
│   ├── mcp_server/server.py   Demo financial MCP server
│   └── proxy_entrypoint.py    Demo proxy startup
├── docker/
│   ├── docker-compose.demo.yml
│   ├── Dockerfile.server
│   ├── Dockerfile.proxy
│   └── Dockerfile.agent
├── docker-compose.yml     Production proxy + OPA stack
├── tests/
│   └── test_mcp_authz.py  20 tests across all layers
└── pyproject.toml
```

---

## Running tests

```bash
pip install ".[dev]"
pytest tests/ -v
```

---

## References

- [RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [SPIFFE/SPIRE workload identity](https://spiffe.io)
- [Open Policy Agent](https://www.openpolicyagent.org)
- [Identity Management for Agentic AI (arXiv 2510.25819)](https://arxiv.org/abs/2510.25819)
- [MCP Specification](https://spec.modelcontextprotocol.io)

---

## License

MIT
