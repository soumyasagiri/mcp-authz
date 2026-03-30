# How the policy engine works

## What policy enforcement means here

After the delegation chain passes, the next question is simpler: is this specific agent allowed to call this specific tool right now?

This is access control at the tool level. Not "does the agent have a valid token" but "does the agent's token include the right scopes for this tool, and is this tool allowed at all."

---

## Two modes

**Built-in engine (default)**

Works with no external dependencies. Evaluates three rules in order:

1. Is the tool on the permanent block list?
2. Does the agent's principal type match the rules for that type?
3. Do the agent's effective scopes cover this tool?

If all three pass, the call is allowed.

**OPA mode**

[Open Policy Agent](https://www.openpolicyagent.org) is the policy engine used in production by Google, Netflix, Atlassian, Intuit, and hundreds of other companies. It evaluates policies written in a language called Rego and returns allow or deny decisions in milliseconds.

mcp-authz can send every authorization decision to a running OPA server instead of evaluating locally. This gives you full expressiveness: time-based rules, attribute-based access control, integration with external data sources, policy-as-code that your security team can review and update without touching application code.

To use OPA mode, set `OPA_URL` to your OPA server and put your policy in `policies/reference/universal.rego`.

---

## The permanent block list

Some tools should never be called by an automated agent under any circumstances. No token, no scope, no delegation chain overrides the permanent block list.

Default blocked tools:

- `transfer_funds`
- `code_execute`
- `eval`
- `exec`
- `export_all_data`
- `delete_account`
- `shell_execute`
- `system_call`
- `run_command`

The reasoning: these tools either move money, execute arbitrary code, or export bulk data. The risk of accidental or malicious execution in an automated context is high enough that they should require explicit human review before being added back.

To remove a tool from the block list, edit your configuration. The change is intentional and visible in your config history.

---

## Scope-to-tool coverage

For tools not on the block list, the agent's effective scopes are checked against the tool being called.

Effective scopes are the intersection of scopes across the entire delegation chain. If Alice granted `account:read transaction:read` but the orchestrator only passed down `account:read` to the sub-agent, the effective scope is `account:read`. The sub-agent cannot call `transaction_list` even though Alice's original token included that scope.

The built-in engine checks whether any effective scope covers the tool by matching the scope prefix to the tool name prefix. `account:read` covers `account_balance` and `account_summary`. It does not cover `transaction_list` or `transfer_funds`.

---

## Custom Rego policy

If the built-in rules are not enough, write your own in Rego:

```rego
package mcp.authz

default allow := false

blocked_tools := {
    "transfer_funds", "code_execute", "eval",
    "export_all_data", "delete_account"
}

allow if {
    not input.tool.name in blocked_tools
    input.agent.principal_type == "human_delegated_agent"
    count(input.agent.effective_scopes) > 0
    tool_scope_covered
}

tool_scope_covered if {
    some scope in input.agent.effective_scopes
    startswith(input.tool.name, split(scope, ":")[0])
}

# Time-based rule: only allow financial tools during business hours
allow if {
    input.tool.name == "account_balance"
    input.agent.principal_type == "service_agent"
    time.clock(time.now_ns())[0] >= 9
    time.clock(time.now_ns())[0] < 17
}
```

The input object available in Rego:

```json
{
  "tool": {
    "name": "account_balance",
    "params": {"account_id": "123"},
    "server_id": "financial-mcp"
  },
  "agent": {
    "subject": "agent:financial-assistant",
    "root_principal": "user:alice@yourcompany.com",
    "principal_type": "human_delegated_agent",
    "effective_scopes": ["account:read"],
    "is_human_delegated": true
  },
  "chain": {
    "depth": 2,
    "principals": ["user:alice@yourcompany.com", "agent:financial-assistant"]
  }
}
```

---

## Why OPA specifically

OPA is the de facto standard for policy-as-code in production systems. Netflix uses it to manage access to their streaming infrastructure. Google uses it internally for cloud resource policies. Atlassian uses it across their product suite.

The advantage over custom authorization code is separation of concerns. The policy lives in one place, reviewable by your security team, auditable, versioned in git, deployable without a code release. When a regulation changes or a new threat model emerges, you update the policy file. Nothing else changes.

---

## References

- [Open Policy Agent documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego policy language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [OPA in production at Netflix](https://netflixtechblog.com/how-netflix-is-solving-authorization-across-their-cloud-558f70e5a5a4)
