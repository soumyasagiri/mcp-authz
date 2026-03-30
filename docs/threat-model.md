# Threat Model

## Scope

This threat model covers authorization threats specific to Model Context Protocol (MCP) tool calls in agentic AI systems. It describes the attack surface, threat categories, and how mcp-authz addresses each.

It does not cover threats to the MCP server itself, the underlying infrastructure, or the AI model's reasoning process.

---

## System components

```
[Human / Service Principal]
        |
        | delegates authority via JWT
        v
[AI Agent / Orchestrator]
        |
        | tools/call + Bearer JWT
        v
[mcp-authz proxy]         <-- enforcement boundary
        |
        | authorized requests only
        v
[MCP Server]
        |
        v
[Tools: databases, APIs, file systems, financial systems]
```

**Trust boundary:** The mcp-authz proxy is the enforcement boundary. Everything above it is untrusted input. Everything below it receives only authorized requests.

---

## Threat actors

| Actor | Description | Capability |
|-------|-------------|------------|
| External attacker | Obtained a valid agent token via interception or credential theft | Can present valid JWT, cannot forge signatures |
| Malicious sub-agent | Agent in a multi-agent pipeline attempting privilege escalation | Can generate its own tokens, cannot forge parent signatures |
| Compromised agent | Legitimate agent whose behavior has been manipulated via prompt injection or supply chain attack | Has valid token, calls tools in unusual patterns |
| Insider threat | Developer or operator with access to token generation infrastructure | Can issue valid tokens with crafted claims |

---

## STRIDE threat analysis

### Spoofing

**Threat S1: Token forgery**
An attacker attempts to forge a JWT to impersonate a legitimate agent or claim elevated permissions.

*Mitigation:* Layer 1 verifies RSA/EC signatures against the JWKS endpoint. Forged tokens without a valid signature are rejected. Severity: Critical. Status: Mitigated.

**Threat S2: Identity spoofing via stolen token**
An attacker steals a valid token and presents it as their own.

*Mitigation:* JTI replay protection tracks every seen token ID. A stolen token used after the legitimate holder has already used it is rejected as a replay attack. Severity: High. Status: Mitigated.

---

### Tampering

**Threat T1: Delegation chain amplification**
A sub-agent tampers with its token to claim scopes its parent never granted, escalating from `account:read` to `account:admin`.

*Mitigation:* Layer 1 enforces the attenuation invariant: `scopes[child] ⊆ scopes[parent]` for every link in the chain. Any amplification is detected and rejected with `INVALID_DELEGATION_CHAIN`. Severity: Critical. Status: Mitigated.

**Threat T2: act claim manipulation**
An attacker modifies the `act` claim chain to remove delegation links or substitute a trusted principal.

*Mitigation:* The entire JWT including nested `act` claims is signature-verified. Any modification invalidates the signature. Severity: High. Status: Mitigated.

---

### Repudiation

**Threat R1: Denied tool call execution**
An agent denies having called a sensitive tool.

*Mitigation:* The authorization log records every ALLOW and DENY decision with timestamp, agent subject, tool name, delegation chain depth, decision reason, and request ID. Log entries are append-only. Severity: Medium. Status: Mitigated.

---

### Information disclosure

**Threat I1: Tool enumeration via error messages**
An attacker probes which tools exist by observing different error responses.

*Mitigation:* All denied requests return a uniform `403 AUTHORIZATION_ERROR` structure. The specific reason (blocked tool, scope mismatch, chain violation) is logged internally but not exposed in detail to the caller. Severity: Low. Status: Partially mitigated.

---

### Denial of service

**Threat D1: Brute force token validation**
An attacker floods the proxy with invalid tokens to exhaust resources or discover valid credentials.

*Mitigation:* The `AuthFailureRateLimiter` implements a token-bucket rate limiter per source IP. Sources exceeding the failure threshold within the window are blocked with `RATE_LIMITED`. Severity: Medium. Status: Mitigated.

**Threat D2: JWKS endpoint unavailability**
The JWKS endpoint goes down, preventing token validation.

*Mitigation:* The JWKS cache serves previously fetched keys for up to 300 seconds. Short outages do not interrupt service. Extended outages cause fail-closed behavior: new tokens cannot be validated. Severity: Medium. Status: Partially mitigated (fail-closed is the correct behavior for authorization infrastructure).

---

### Elevation of privilege

**Threat E1: Warmup bypass attack**
An attacker makes legitimate calls to build a favorable behavioral baseline, then pivots to malicious behavior expecting the baseline to mask the anomaly.

*Mitigation:* Layer 3 uses exponentially time-weighted moving average (EWMA) baselines. Recent behavior is weighted more heavily than historical behavior. A pivot to malicious activity causes an immediate score spike regardless of prior history. Severity: High. Status: Mitigated.

**Threat E2: Scope creep via service agent impersonation**
An attacker presents a token without a delegation chain, claiming service agent status to bypass attenuation checks.

*Mitigation:* Service agents go through full policy evaluation. The permanent block list applies to all principal types. Scope coverage is checked against the tool being called. Severity: Medium. Status: Mitigated.

**Threat E3: Permanently blocked tool access**
An attacker attempts to call `transfer_funds`, `code_execute`, or other permanently blocked tools via any means: crafted scopes, service agent tokens, or OPA bypass.

*Mitigation:* The permanent block list is evaluated before OPA and before scope checks. No token or policy can override it. It is the first check, not the last. Severity: Critical. Status: Mitigated.

---

## MITRE ATT&CK mapping

| Technique | ID | mcp-authz layer |
|-----------|-----|----------------|
| Valid Accounts | T1078 | Layer 1: JTI replay protection |
| Abuse Elevation Control Mechanism | T1548 | Layer 1: Attenuation invariant |
| Credential Access: Steal Application Token | T1528 | Layer 1: Signature verification + JTI |
| Discovery: Account Discovery | T1087 | Layer 3: Behavioral anomaly detection |
| Lateral Movement: Use Alternate Auth Material | T1550 | Layer 1: Delegation chain validation |
| Exfiltration: Automated Exfiltration | T1020 | Layer 2: Permanent block list + Layer 3 |
| Privilege Escalation: Token Impersonation | T1134 | Layer 1: Signature verification |

---

## Known residual risks

**Prompt injection.** mcp-authz enforces at the tool call layer. If the model's reasoning has been manipulated before a call is made, and the resulting call is within the agent's authorized scope, mcp-authz will allow it. Defense requires prompt-layer controls outside the scope of this library.

**Model identity.** mcp-authz binds authorization to the token, not to the specific model instance that generated the call. If two agents share a token, mcp-authz cannot distinguish between them.

**In-memory state.** JTI store and behavioral baselines are in memory. Proxy restart resets both. For production deployments requiring persistence across restarts, a Redis-backed implementation is recommended.

**Clock skew.** Token expiry enforcement includes a configurable clock skew tolerance (default 30 seconds). Tokens can be valid for up to 30 seconds beyond their stated expiry.

---

## References

- [STRIDE threat modeling methodology](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [MITRE ATT&CK for Enterprise](https://attack.mitre.org)
- [RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [Identity Management for Agentic AI, arXiv:2510.25819](https://arxiv.org/abs/2510.25819)
