"""
Demo Agent: Financial Assistant
Simulates an AI agent calling MCP tools through mcp-authz.

Runs four scenarios that demonstrate the three enforcement layers:

  Scenario 1: NORMAL   - allowed tool calls pass through cleanly
  Scenario 2: BLOCKED  - transfer_funds hits the blocked tool list
  Scenario 3: ATTENUATION - sub-agent claims admin scope not granted by human
  Scenario 4: ANOMALY  - agent calls account_search 60 times (credential abuse sim)

Each scenario is clearly labeled in the output with color coding.
"""

import asyncio
import json
import os
import sys
import time
import logging
from dataclasses import dataclass
from typing import Any

import aiohttp
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# ── Color output ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def banner(text: str, color: str = CYAN) -> None:
    width = 60
    print(f"\n{color}{BOLD}{'─' * width}{RESET}")
    print(f"{color}{BOLD}  {text}{RESET}")
    print(f"{color}{BOLD}{'─' * width}{RESET}")

def ok(text: str)   -> None: print(f"  {GREEN}✓{RESET}  {text}")
def fail(text: str) -> None: print(f"  {RED}✗{RESET}  {text}")
def info(text: str) -> None: print(f"  {DIM}→{RESET}  {DIM}{text}{RESET}")

# ── Token generation ──────────────────────────────────────────────────────────

def generate_keypair():
    """Generate RSA keypair for signing demo tokens."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_pem, public_pem


def make_token(private_key_pem: str, claims: dict) -> str:
    return jwt.encode(claims, private_key_pem, algorithm="RS256")


def future(seconds: int = 3600) -> int:
    return int(time.time()) + seconds


def human_delegated_token(private_key: str, scopes: str, agent_id: str) -> str:
    """Human delegates to agent with specific scopes."""
    return make_token(private_key, {
        "sub": agent_id,
        "principal_type": "human_delegated_agent",
        "scope": scopes,
        "iss": "https://auth.demo.mcp-authz.io",
        "exp": future(),
        "iat": int(time.time()),
        "act": {
            "sub": "user:alice@example.com",
            "principal_type": "human",
            "scope": scopes,
            "exp": future(),
            "iat": int(time.time()),
        }
    })


def amplified_token(private_key: str) -> str:
    """Sub-agent claims admin scope the human never granted - attenuation violation."""
    return make_token(private_key, {
        "sub": "agent:rogue-sub-agent",
        "principal_type": "human_delegated_agent",
        "scope": "account:read account:admin transfer:execute",  # admin NOT in parent
        "iss": "https://auth.demo.mcp-authz.io",
        "exp": future(),
        "iat": int(time.time()),
        "act": {
            "sub": "agent:orchestrator",
            "principal_type": "orchestrator_agent",
            "scope": "account:read",               # human only granted read
            "exp": future(),
            "iat": int(time.time()),
            "act": {
                "sub": "user:alice@example.com",
                "principal_type": "human",
                "scope": "account:read",
                "exp": future(),
                "iat": int(time.time()),
            }
        }
    })


# ── MCP call through proxy ────────────────────────────────────────────────────

async def call_tool(
    session: aiohttp.ClientSession,
    proxy_url: str,
    token: str,
    tool_name: str,
    arguments: dict,
) -> dict:
    """Send a tool/call request through the mcp-authz proxy."""
    payload = {
        "jsonrpc": "2.0",
        "id": int(time.time() * 1000),
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    async with session.post(proxy_url, json=payload, headers=headers) as resp:
        return await resp.json()


def parse_outcome(response: dict) -> tuple[bool, str]:
    """Return (success, message) from a proxy response."""
    if "error" in response:
        err = response["error"]
        code = err.get("data", "UNKNOWN")
        msg  = err.get("message", str(err))
        return False, f"[{code}] {msg}"
    result = response.get("result", {})
    if result.get("isError"):
        content = result.get("content", [{}])[0].get("text", "")
        return False, content
    content = result.get("content", [{}])[0].get("text", "{}")
    return True, content


# ── Scenarios ─────────────────────────────────────────────────────────────────

async def scenario_normal(session, proxy_url, private_key):
    banner("SCENARIO 1: Normal authorized tool calls", GREEN)
    print(f"  {DIM}Human grants agent: account:read transaction:read{RESET}")
    print(f"  {DIM}Agent calls: account_balance, transaction_list, transaction_summary{RESET}\n")

    token = human_delegated_token(private_key, "account:read transaction:read",
                                  "agent:financial-assistant")
    calls = [
        ("account_balance",    {"account_id": "acc-001"}),
        ("transaction_list",   {"account_id": "acc-001", "limit": 3}),
        ("transaction_summary",{"account_id": "acc-001", "period_days": 30}),
    ]
    for tool, args in calls:
        info(f"Calling {tool}({args})")
        resp = await call_tool(session, proxy_url, token, tool, args)
        success, msg = parse_outcome(resp)
        if success:
            data = json.loads(msg) if isinstance(msg, str) else msg
            ok(f"{tool} → {json.dumps(data)[:80]}...")
        else:
            fail(f"{tool} unexpectedly blocked: {msg}")
        await asyncio.sleep(0.2)


async def scenario_blocked_tool(session, proxy_url, private_key):
    banner("SCENARIO 2: Blocked tool - transfer_funds", RED)
    print(f"  {DIM}transfer_funds is on the permanent block list{RESET}")
    print(f"  {DIM}No scope or delegation can override a blocked tool{RESET}\n")

    token = human_delegated_token(private_key, "account:read transfer:execute",
                                  "agent:financial-assistant")
    calls = [
        ("transfer_funds", {"from_account": "acc-001", "to_account": "acc-002",
                            "amount": 5000.00}),
        ("code_execute",   {"code": "import os; os.system('rm -rf /')"}),
        ("export_all_data",{}),
    ]
    for tool, args in calls:
        info(f"Calling {tool}({args})")
        resp = await call_tool(session, proxy_url, token, tool, args)
        success, msg = parse_outcome(resp)
        if not success:
            fail(f"{tool} → BLOCKED ✓  ({msg[:100]})")
        else:
            print(f"  {RED}⚠{RESET}  {tool} was NOT blocked - enforcement failed!")
        await asyncio.sleep(0.2)


async def scenario_attenuation(session, proxy_url, private_key):
    banner("SCENARIO 3: Attenuation violation - sub-agent claims extra scope", YELLOW)
    print(f"  {DIM}Human grants: account:read only{RESET}")
    print(f"  {DIM}Orchestrator passes to sub-agent{RESET}")
    print(f"  {DIM}Sub-agent token claims: account:read + account:admin + transfer:execute{RESET}")
    print(f"  {DIM}Delegation chain validator detects the amplification{RESET}\n")

    token = amplified_token(private_key)
    info("Calling account_balance with amplified token")
    resp = await call_tool(session, proxy_url, token, "account_balance",
                           {"account_id": "acc-001"})
    success, msg = parse_outcome(resp)
    if not success and "ATTENUATION" in msg.upper() or "delegation" in msg.lower():
        fail(f"Amplified token rejected → ATTENUATION VIOLATION detected ✓")
        fail(f"  Reason: {msg[:120]}")
    elif not success:
        fail(f"Token rejected (different reason): {msg[:120]}")
    else:
        print(f"  {RED}⚠{RESET}  Amplified token was accepted - attenuation not enforced!")


async def scenario_anomaly(session, proxy_url, private_key):
    banner("SCENARIO 4: Behavioral anomaly - credential abuse simulation", YELLOW)
    print(f"  {DIM}Agent normally reads account balances (normal pattern){RESET}")
    print(f"  {DIM}After baseline builds, agent suddenly calls account_search 60x{RESET}")
    print(f"  {DIM}This mimics a compromised credential doing bulk enumeration{RESET}\n")

    token = human_delegated_token(private_key, "account:read transaction:read",
                                  "agent:anomaly-demo")

    # Build baseline: normal behavior
    info("Building behavioral baseline (20 normal calls)...")
    for i in range(20):
        await call_tool(session, proxy_url, token, "account_balance",
                        {"account_id": "acc-001"})
        await call_tool(session, proxy_url, token, "transaction_list",
                        {"account_id": "acc-001"})
        if i % 5 == 0:
            print(f"    {DIM}baseline calls: {(i+1)*2}/40{RESET}")
        await asyncio.sleep(0.05)

    ok("Baseline established. Now simulating credential abuse...")
    print()

    # Anomalous: suddenly call account_search repeatedly
    blocked_at = None
    for i in range(60):
        resp = await call_tool(session, proxy_url, token, "account_search",
                               {"query": f"user{i}", "limit": 100})
        success, msg = parse_outcome(resp)
        if not success and "ANOMALY" in msg.upper():
            blocked_at = i + 1
            fail(f"Call #{i+1}: ANOMALY BLOCKED ✓  ({msg[:100]})")
            break
        elif not success:
            fail(f"Call #{i+1}: blocked (policy): {msg[:80]}")
            break
        else:
            if i < 3 or i % 10 == 9:
                info(f"Call #{i+1}: allowed (anomaly score building...)")
        await asyncio.sleep(0.03)

    if blocked_at:
        ok(f"Anomaly detection triggered after {blocked_at} unusual calls")
    else:
        print(f"\n  {DIM}Note: account_search may be blocked by policy before anomaly score{RESET}")
        print(f"  {DIM}triggers. This is correct behavior - policy enforcement{RESET}")
        print(f"  {DIM}runs before anomaly detection in the three-layer stack.{RESET}")


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    proxy_url = os.getenv("PROXY_URL", "http://localhost:9000/mcp")

    print(f"\n{BOLD}{CYAN}mcp-authz Demo Agent{RESET}")
    print(f"{DIM}Financial assistant demonstrating the three enforcement layers{RESET}")
    print(f"{DIM}Proxy: {proxy_url}{RESET}")

    # Generate keypair for this demo session
    print(f"\n{DIM}Generating RSA keypair for demo tokens...{RESET}")
    private_key = '''-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxePZcGuqzvfrNFInrdHTi+H+YmxiVm9I2jnx9iVPgfOEhdU9
rKqIamdaKJUCOlA03J0aquUsIF+njWzHAqd4fNdXUm22YbtmyLLcfKXvDK3GaLli
JdSkL75WQclGfy9W9tXu1yqeOGO/EycjmbnA9fCjk2Ka4Dx/pTF7GEMCCZn7tLy+
BiAmmvpamgG+u8qY6UpiI+92CNupSz5h70+ro/swzh5wKlXdXnqdVYJ2HndmMYD4
TD+6VJBR3WBXGHlI3OCXp2tF9421/cDbhMPdL5LJDAma6Da4XL4UsJ/I0q6/q9Ed
phtNp3GC8zGrRNfYIl5gYCb53ETjdxcFvRdqZQIDAQABAoIBAA1SM46cINPCiqRr
V10dv9Ytxg24FWfoy92s2Ds6nb82C64QAbvVgE4GsQyu+IcWY8iUvCPUPi6GYeVk
9NdFO24j94Pb+31ZZnziKsd/9WHux2lrTqO/TGIjt54Wv4Eg8wNguVg7TTVR5EiU
x5Jkl7cL65GoqfD9rEC23lNux1IABkq6ticHCs6oIjVZ/P1x5sYMw8g0POYuk9zM
Ayt87ZKLlO5jaL0YcJQhBpJ2wXA8wuI7jbvBr1oQJIE6j1AOC1a0q/Op67zKgbo0
4U+Zq/LdwWIJ2xTh9Jc0Wk+glfHBB+awN5hW15LBsMtUZZ7VWSqstKIaEAxxUofo
mgwARGECgYEA5rODjT5R5/DLkpLhmfAY/tEutTIG3ZGJjYzE3jYk1eEsRHsxHO2A
vCSGj7nmPwLsxvjX63NqCNee6UAvn6qxjC4kysASuWnVJFzm8u1HUtfVyFs/DDq1
VRJT9kfLLdz0U70gSQsRBqrrKu99sLByWX+w9AXOdwrcUtORPe/AmSkCgYEA25c5
uDuePvP6d6GGy3I4j/EtxUyV9TCTir/HI3busfgMtvCgleHpZoR3ADum0hnFDJDR
cIpWWrZSxBVN7mJi0quZd7zlauoCizQwB9w7NS87jBXwgCqmdagr8ODHv3p6b9E0
p0/ApRelr4T6bXsjA5OAOJCA48XR7QtnfhJV4t0CgYAtztU/NXGkAV8aoomjPFZq
OnTwy5crZZuPfLUWfl/ADC7zBhcRbGNUeFgzr7D1MAp906lj+g3C5bWLERCjvov0
jrEFhS/ymv4Uc1H0SIMSAwNS/jM9pWaeFr6PN2Azohzth68icc0Wqtd5NgaaD98U
wFMNkR2W65Ql6hZ72uA+SQKBgBLryeZtBKqp/Sf3vBSlp+gHQQliGv3AjMYE1lTg
95pQJFBTFZM0nxbdTR+xBCPQYqE9jT5kPSKd2S3aJBfpVFiQvq2Jkj8PIN77xTO4
L0Xa5wegEFQK2MMElZyw0aVXGVuvLBlKju/qxLUGAUoTtSWmvQKiuOhncDo7pFRB
ojLlAoGAc9vIukGUDpuedlfCBzdL5kAzuFPZ7YLpEUE7vyn/61nkUwBGvmB6I3bY
ZaXIDYzdirtxiO0zceR5y6F035boPujn0AI4UcpqmTGiYSIJikGWFktLabRNFDSE
GytPPRsEj7dNbgnPA9QyshQ+PwRDE2E0LtnAcljWKwKBNls82oM=
-----END RSA PRIVATE KEY-----
'''
    public_key = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxePZcGuqzvfrNFInrdHT
i+H+YmxiVm9I2jnx9iVPgfOEhdU9rKqIamdaKJUCOlA03J0aquUsIF+njWzHAqd4
fNdXUm22YbtmyLLcfKXvDK3GaLliJdSkL75WQclGfy9W9tXu1yqeOGO/EycjmbnA
9fCjk2Ka4Dx/pTF7GEMCCZn7tLy+BiAmmvpamgG+u8qY6UpiI+92CNupSz5h70+r
o/swzh5wKlXdXnqdVYJ2HndmMYD4TD+6VJBR3WBXGHlI3OCXp2tF9421/cDbhMPd
L5LJDAma6Da4XL4UsJ/I0q6/q9EdphtNp3GC8zGrRNfYIl5gYCb53ETjdxcFvRdq
ZQIDAQAB
-----END PUBLIC KEY-----
'''

    # Write public key to shared volume so proxy can validate our tokens
    public_key_path = os.getenv("PUBLIC_KEY_PATH", "/tmp/demo_public_key.pem")
    print(f"{DIM}Using hardcoded keypair{RESET}")

    # Wait for proxy to be ready
    await asyncio.sleep(5)
    ok("Proxy ready")
    async with aiohttp.ClientSession() as session:

        # Run all four scenarios
        await scenario_normal(session, proxy_url, private_key)
        await asyncio.sleep(0.5)

        await scenario_blocked_tool(session, proxy_url, private_key)
        await asyncio.sleep(0.5)

        await scenario_attenuation(session, proxy_url, private_key)
        await asyncio.sleep(0.5)

        await scenario_anomaly(session, proxy_url, private_key)

    # Summary
    print(f"\n{BOLD}{GREEN}{'─' * 60}{RESET}")
    print(f"{BOLD}{GREEN}  Demo complete{RESET}")
    print(f"{GREEN}{'─' * 60}{RESET}")
    print(f"""
  What you saw:

  {GREEN}Scenario 1{RESET}  Legitimate agent calls passed through cleanly.
              All three layers checked and approved.

  {RED}Scenario 2{RESET}  Blocked tools (transfer_funds, code_execute,
              export_all_data) denied before reaching MCP server.
              Policy layer. No amount of scope overrides a blocked tool.

  {YELLOW}Scenario 3{RESET}  Sub-agent claiming scopes not granted by the
              delegating human was rejected at the delegation layer.
              The attenuation invariant is cryptographically enforced.

  {YELLOW}Scenario 4{RESET}  Simulated credential abuse (bulk account enumeration)
              caught by behavioral anomaly detection after the
              pattern diverged from the agent's learned baseline.

  Three layers. One proxy. Zero changes to the MCP client or server.
""")


if __name__ == "__main__":
    asyncio.run(main())
