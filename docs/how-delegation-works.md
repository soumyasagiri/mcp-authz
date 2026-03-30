# How delegation chain validation works

## The core problem

When an AI agent calls a tool, it presents a token. The token says "this agent is allowed to do things." But who decided that? Did a human actually authorize this agent? Did an orchestrator pass down its own permissions to a sub-agent? Did the sub-agent quietly give itself more permissions than it was granted?

Without answers to these questions, a token is just a claim. Anyone can generate a token. Anyone who steals a token inherits everything in it.

The delegation chain validator answers all three questions cryptographically.

---

## What a delegation chain looks like

A delegation chain is a nested structure inside the JWT token. The outermost claim describes the current actor. Nested inside it is an `act` claim describing who authorized the current actor. Nested inside that is another `act` claim describing who authorized the authorizer, and so on back to the original human or trusted service.

```json
{
  "sub": "agent:financial-assistant",
  "principal_type": "human_delegated_agent",
  "scope": "account:read transaction:read",
  "iss": "https://auth.yourcompany.com",
  "exp": 1774855537,
  "act": {
    "sub": "user:alice@yourcompany.com",
    "principal_type": "human",
    "scope": "account:read transaction:read",
    "exp": 1774855537
  }
}
```

This token says: the financial assistant agent is acting on behalf of Alice. Alice granted it `account:read` and `transaction:read`. The whole thing is signed by your auth server.

In a multi-agent pipeline the chain goes deeper:

```json
{
  "sub": "agent:sub-agent",
  "scope": "account:read",
  "act": {
    "sub": "agent:orchestrator",
    "scope": "account:read",
    "act": {
      "sub": "user:alice@yourcompany.com",
      "principal_type": "human",
      "scope": "account:read"
    }
  }
}
```

---

## The attenuation invariant

The central rule mcp-authz enforces is called the attenuation invariant:

> Every step in the chain can only grant permissions it actually has. You cannot give away what you do not have.

Formally: `scopes[i] ⊆ scopes[i-1]` for every level i in the chain.

If Alice grants `account:read`, the orchestrator can give the sub-agent `account:read` or nothing. It cannot give `account:admin`. If the sub-agent's token claims `account:admin`, the validator rejects it immediately regardless of any other checks.

This is why this property is cryptographic rather than conventional. The chain is signed. A sub-agent cannot modify its own token to claim more permissions. If it tries, the signature verification fails. If it generates a fresh token claiming elevated permissions, it cannot forge the signature of your auth server.

---

## Replay attack prevention

A token has an expiry time. But between issuance and expiry, anyone with a copy of the token can use it. If an attacker intercepts a token mid-flight and the original agent finishes using it, the attacker still has a valid token.

mcp-authz prevents this with `jti` (JWT ID) claim tracking. Each token should carry a unique identifier in the `jti` claim. The validator records every `jti` it has seen along with its expiry time. If the same `jti` arrives twice, the second request is rejected as a replay attack.

The store is bounded in size and automatically evicts expired entries so it does not grow without limit.

To use this feature, your auth server needs to include a unique `jti` in each token it issues. This is one line of code in any standard auth library.

---

## Key freshness

The validator fetches your public keys from a JWKS endpoint to verify token signatures. Keys rotate. If mcp-authz caches a key indefinitely and that key gets compromised, it keeps trusting tokens signed with the compromised key even after rotation.

The JWKS cache has a configurable TTL, defaulting to 300 seconds. This matches the SVID rotation period used by SPIFFE/SPIRE in production workload identity deployments. After the TTL expires the cache is invalidated and keys are re-fetched on the next request.

---

## Principal types

mcp-authz recognizes three principal types and applies different validation rules to each:

**human_delegated_agent**: An agent acting on behalf of a human. Must carry an `act` chain. The root of the chain must be a human principal. Full attenuation enforcement applies.

**service_agent**: An autonomous machine-to-machine agent with no human delegation. No `act` chain required. Validated against a scope allowlist rather than a delegation chain.

**orchestrator_agent**: An agent that spawns sub-agents. Must carry an `act` chain. Delegation depth is bounded to prevent unbounded recursive delegation.

---

## What happens when validation fails

Every failure returns a 403 with a structured error code:

- `INVALID_DELEGATION_CHAIN`: Signature verification failed, issuer not trusted, or chain is malformed
- `ATTENUATION_VIOLATION`: Sub-agent claimed scopes its parent did not grant
- `TOKEN_EXPIRED`: One or more links in the chain have expired
- `REPLAY_ATTACK`: The jti has already been seen
- `DEPTH_EXCEEDED`: The chain is longer than the configured maximum

---

## References

- [RFC 8693: OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [RFC 7519: JSON Web Token (JWT), Section 4.1.7 on jti](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7)
- [SPIFFE/SPIRE: SVID rotation](https://spiffe.io/docs/latest/spire-about/spire-concepts/)
- [Identity Management for Agentic AI, arXiv:2510.25819](https://arxiv.org/abs/2510.25819)
