# mcp-authz

**Your AI agent can call any tool it can reach. Nothing stops it.**

mcp-authz is the authorization layer that MCP does not have. A proxy that sits between your agent and your MCP server and enforces what the agent is actually allowed to do.

[![CI](https://github.com/soumyasagiri/mcp-authz/actions/workflows/ci.yml/badge.svg)](https://github.com/soumyasagiri/mcp-authz/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![RFC 8693](https://img.shields.io/badge/RFC-8693-green.svg)](https://www.rfc-editor.org/rfc/rfc8693)

---

## The problem

MCP lets AI agents call tools: read files, query databases, send emails, transfer money, whatever your server exposes.

Nothing in the protocol controls which agent can call which tool. Every agent with a valid token has access to everything. If the token gets stolen, the attacker has the same access. If a sub-agent in a pipeline quietly claims more permissions than it was granted, nothing catches it. If a compromised agent starts bulk-exporting customer data one record at a time, each individual call looks authorized.

Teams building agentic systems in sensitive environments keep hitting the same wall: there is no standard way to answer the question of who controls what the agent can do.

mcp-authz is the solution.

---

## See it working before reading anything else

```bash
git clone https://github.com/soumyasagiri/mcp-authz.git
cd mcp-authz
docker compose -f docker/docker-compose.demo.yml up --build
```

Watch the agent container. Four scenarios run automatically against a live financial MCP server.

```
SCENARIO 1: Normal authorized calls
  -> account_balance({'account_id': 'acc-001'})
  OK  {"balance": 12450.0, "currency": "USD"}
  -> transaction_list({'account_id': 'acc-001'})
  OK  {"transactions": [...], "count": 3}

SCENARIO 2: Dangerous tools blocked before reaching your server
  -> transfer_funds({'amount': 5000})
  BLOCKED  [POLICY_DENIED] Tool 'transfer_funds' is blocked
  -> code_execute({'code': "os.system('rm -rf /')"})
  BLOCKED  [POLICY_DENIED] Tool 'code_execute' is blocked

SCENARIO 3: Sub-agent tries to claim permissions it was never granted
  -> account_balance with amplified token
  BLOCKED  [INVALID_DELEGATION_CHAIN] Agent claims
           {'account:admin', 'transfer:execute'} not
           granted by delegating principal

SCENARIO 4: Stolen credential doing bulk enumeration
  -> account_search x60 rapid calls
  Call 1:  allowed  (score: 0.021)
  Call 10: allowed  (score: 0.340)
  Call 23: BLOCKED  (score: 0.912) Anomaly detected
```

---

## How it works

Three enforcement layers. Every tool call goes through all three before reaching your server.

```
                        Your Application
                              |
              MCP Client (Claude / LangChain / AutoGen)
                              |
                   Bearer JWT token + tools/call
                              |
                              v
+------------------------------------------------------------------+
|                        mcp-authz proxy                           |
|                                                                  |
|  +------------------------------------------------------------+  |
|  |  LAYER 1: Delegation Chain Validator          (RFC 8693)   |  |
|  |                                                            |  |
|  |  Parse JWT act claim chain                                 |  |
|  |  Verify RSA/EC signature against JWKS                     |  |
|  |  Enforce: scopes[child] subset of scopes[parent]          |  |
|  |  Check delegation depth <= max_depth                      |  |
|  |  Detect replayed tokens via jti tracking                  |  |
|  |                                                            |  |
|  |  DENY --> 403 INVALID_DELEGATION_CHAIN                    |  |
|  +-----------------------------+------------------------------+  |
|                                | chain valid                     |
|  +-----------------------------v------------------------------+  |
|  |  LAYER 2: Tool Policy Engine          (OPA / built-in)    |  |
|  |                                                            |  |
|  |  Permanent block list (transfer_funds, code_execute ...)  |  |
|  |  Principal type rules (human_delegated / service / orch)  |  |
|  |  Scope-to-tool coverage check                             |  |
|  |  Custom Rego policies via OPA (optional)                  |  |
|  |                                                            |  |
|  |  DENY --> 403 POLICY_DENIED                               |  |
|  +-----------------------------+------------------------------+  |
|                                | policy allows                   |
|  +-----------------------------v------------------------------+  |
|  |  LAYER 3: Behavioral Anomaly Detector                     |  |
|  |                                                            |  |
|  |  Per-agent EWMA time-weighted baseline                    |  |
|  |  Z-score call frequency anomaly detection                 |  |
|  |  Jaccard parameter structure deviation                    |  |
|  |  Block threshold configurable (default 0.9)               |  |
|  |                                                            |  |
|  |  DENY --> 403 ANOMALY_BLOCKED                             |  |
|  +-----------------------------+------------------------------+  |
|                                | all layers passed               |
|  Authorization log: every decision with full context             |
+--------------------------------+---------------------------------+
                                 |
                                 v
                    Your MCP Server (unchanged)
```

**Layer 1** validates the chain of custody in the token. Every agent token must trace back to an authorized human or trusted service. Permissions can only narrow as they flow down the chain, never expand. A sub-agent cannot claim scopes its parent never held. Enforced cryptographically via JWT signature verification.

**Layer 2** evaluates every tool call against policy before it reaches your server. Some tools are permanently blocked regardless of token or scope: `transfer_funds`, `code_execute`, `export_all_data`. For everything else, the agent's effective scopes are checked against the tool. Custom policies in Rego via OPA if you need more control.

**Layer 3** builds a per-agent behavioral baseline using exponential time-weighting. Recent behavior counts more than old behavior, which closes the warmup bypass attack where an adversary makes legitimate calls first then pivots. If an agent's pattern suddenly diverges from its own baseline, the call is blocked even though it would be individually authorized.

---

## Install

**Option 1: Docker proxy (zero code changes, recommended)**

Add to your docker-compose. Change your agent to point at port 9000 instead of directly at your MCP server. That is the only change.

```yaml
services:
  mcp-authz:
    image: ghcr.io/soumyasagiri/mcp-authz:latest
    ports:
      - "9000:9000"
    environment:
      UPSTREAM_MCP_URL: "http://your-mcp-server:8080"
      JWKS_URI: "https://your-auth-server/.well-known/jwks.json"

  your-mcp-server:
    image: your-mcp-server:latest
    # nothing changes here
```

**Option 2: Python library**

```bash
pip install mcp-authz
```

```python
from mcp_authz import (
    MCPAuthzProxy,
    DelegationChainValidator,
    ToolPolicyEngine,
    AnomalyDetector,
    AuthorizationError,
)

proxy = MCPAuthzProxy(
    validator=DelegationChainValidator(
        jwks_uri="https://your-auth-server/.well-known/jwks.json",
        enable_replay_protection=True,
    ),
    policy_engine=ToolPolicyEngine(default_deny=True),
    anomaly_detector=AnomalyDetector(block_threshold=0.9),
)

# Before every MCP tool call
try:
    await proxy.authorize(
        token=agent_jwt,
        tool_name="account_balance",
        params={"account_id": "123"},
        mcp_server_id="financial-mcp",
    )
    # Forward to your MCP server
except AuthorizationError as e:
    # e.code is one of:
    # INVALID_DELEGATION_CHAIN
    # POLICY_DENIED
    # ANOMALY_BLOCKED
    # RATE_LIMITED
    raise
```

---

## Who should use this

If your agent can do something that matters, you need an authorization layer in front of it.

**Security engineers** building agentic platforms who need to show compliance and audit teams that agents cannot exceed their granted permissions. The authorization log at `/audit` gives you a structured record of every decision with agent, tool, outcome, and reason.

**Platform engineers** running multi-agent pipelines where an orchestrator delegates to sub-agents. Without delegation chain enforcement, any sub-agent can claim any permission. mcp-authz makes the chain of custody verifiable.

**Developers at regulated companies** (fintech, healthcare, government) who need documented access controls before deploying agents into production environments.

**Anyone who has asked:** if this agent's token gets stolen, what is the blast radius? Without mcp-authz, the answer is everything the MCP server exposes. With it, the blast radius is bounded by policy, anomaly detection fires on unusual patterns, and replayed tokens are rejected.

---

## Use cases

**Financial services.** An agent helps relationship managers pull account summaries and risk scores. It should never initiate transfers or export bulk customer data. mcp-authz blocks those tools permanently regardless of what the model decides to do.

**Enterprise assistants.** Agents connected to HR systems, ticketing, and internal knowledge bases. Each user has different scopes. The agent acting for a standard employee cannot call HR admin APIs. The delegation chain ensures the agent's permissions derive from the specific user it is acting for.

**Multi-agent pipelines.** An orchestrator breaks a task into sub-agents: one for search, one for database queries, one for document generation. Each sub-agent gets only the scopes for its specific task. A compromised sub-agent cannot use another sub-agent's permissions.

**Customer-facing products.** A SaaS agent that interacts with customer accounts. The delegation chain traces back to the authenticated customer and prevents cross-tenant access.

**Security operations.** A SOC agent that reads logs and correlates events. It should read but never write, never modify firewall rules, never delete logs. Policy blocks the write and delete categories permanently.

---

## Edge cases

**Token has no jti claim.** Replay protection is skipped. All other checks still run. Add a unique `jti` per token in your auth server for full replay protection.

**JWKS endpoint is down.** Requests are denied, not allowed. Fail-closed is correct behavior for authorization infrastructure.

**Agent legitimately needs high call frequency.** The time-weighted baseline adapts to the agent's actual pattern over time. What gets flagged is a sudden change from the agent's own history, not absolute call volume.

**Token has no delegation chain.** Treated as a service agent. Goes through policy checks only.

**Need to allow a permanently blocked tool.** Remove it from the block list in configuration. The permanent block list exists for tools where automated execution risk is too high for any scope to override. Removing a tool from it is a deliberate, visible configuration change.

**Performance.** Delegation chain validation adds 1-3ms with a warm JWKS cache. Policy evaluation adds under 1ms. Anomaly detection is O(1) after warmup. Total overhead under 5ms per request.

---

## Security properties

| Property | Implementation |
|----------|---------------|
| Replay attack prevention | JTI tracking with TTL eviction per RFC 7519 |
| Key freshness | JWKS cache TTL 300s, matching SPIRE SVID rotation |
| Warmup bypass prevention | EWMA time-weighted baseline |
| Brute force protection | Token-bucket rate limiter per source IP |
| Authorization log | Every ALLOW and DENY with full context |

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `UPSTREAM_MCP_URL` | required | URL of your MCP server |
| `JWKS_URI` | required | JWKS endpoint for token verification |
| `PUBLIC_KEY_PATH` | optional | RSA public key file, alternative to JWKS |
| `MAX_DELEGATION_DEPTH` | 3 | Maximum delegation chain length |
| `ANOMALY_BLOCK_THRESHOLD` | 0.9 | Anomaly score at which calls are blocked |
| `LOG_LEVEL` | INFO | Logging verbosity |

Authorization log available at `http://your-proxy:9000/audit`.

---


## Production considerations

mcp-authz is production-ready for the authorization logic. A few infrastructure decisions to make before deploying at scale.

**In-memory JTI store.** Replay attack prevention stores seen token IDs in memory. If the proxy restarts, the store resets and a token used before restart could theoretically be replayed within its expiry window. For high-security production deployments, back the JTI store with Redis. Contributions welcome.

**In-memory anomaly baselines.** Per-agent behavioral baselines are stored in memory. Proxy restart loses all baselines and agents start a fresh warmup period. For most deployments this is acceptable. For zero-warmup requirements, persistence layer support is on the roadmap.

**No built-in TLS.** The proxy accepts HTTP. In production, run it behind nginx, a load balancer, or any reverse proxy that terminates TLS. Never expose port 9000 directly to the internet without TLS in front.

**Demo keypair is for demo only.** The Docker demo uses a hardcoded RSA keypair to generate test tokens. This keypair is public. Never use it outside the demo. In production, your auth server generates tokens signed with keys only it holds.

## What it does not do

It does not generate tokens. You need an auth server for that.

It does not prevent prompt injection inside the model's reasoning. It enforces at the tool call layer.

It does not replace access controls on your MCP server. It is a layer in front.

---

## Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
# 21 passed in 0.97s
```

---

## Deep dives

- [Threat model: STRIDE analysis and MITRE ATT\&CK mapping](docs/threat-model.md)
- [How delegation chain validation works](docs/how-delegation-works.md)
- [How the policy engine works](docs/how-policy-works.md)
- [How behavioral anomaly detection works](docs/how-anomaly-detection-works.md)

---

## References

- [RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [Open Policy Agent](https://www.openpolicyagent.org)
- [SPIFFE/SPIRE](https://spiffe.io)
- [Identity Management for Agentic AI, arXiv:2510.25819](https://arxiv.org/abs/2510.25819)
- [MCP Specification](https://spec.modelcontextprotocol.io)

---

MIT License. Issues and PRs welcome.
