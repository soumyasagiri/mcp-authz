import asyncio, logging, os, time
logging.basicConfig(level=logging.INFO, format="%(asctime)s [PROXY] %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

def wait_for_public_key(path, timeout=60):
    logger.info(f"Waiting for public key at {path}...")
    start = time.time()
    while time.time() - start < timeout:
        if os.path.exists(path):
            content = open(path).read().strip()
            if content.startswith("-----BEGIN"):
                logger.info("Public key loaded")
                return content
        time.sleep(1)
    raise RuntimeError(f"Public key not found after {timeout}s")

async def main():
    from mcp_authz import MCPAuthzProxy, DelegationChainValidator, ToolPolicyEngine, AnomalyDetector, run_proxy_server
    upstream = os.getenv("UPSTREAM_MCP_URL", "http://mcp-server:8080")
    host = os.getenv("PROXY_HOST", "0.0.0.0")
    port = int(os.getenv("PROXY_PORT", "9000"))
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
    validator = DelegationChainValidator(public_key=public_key, max_delegation_depth=3)
    policy_engine = ToolPolicyEngine(default_deny=True)
    anomaly_detector = AnomalyDetector(window_seconds=3600, observe_only_during_warmup=True)
    def on_deny(r):
        logger.warning(f"DENIED tool={r.tool_name} reason={r.policy_decision.reason if r.policy_decision else 'chain_invalid'}")
    def on_anomaly(s):
        logger.warning(f"ANOMALY tool={s.tool_name} score={s.score:.3f}")
    proxy = MCPAuthzProxy(validator=validator, policy_engine=policy_engine, anomaly_detector=anomaly_detector, on_deny=on_deny, on_anomaly=on_anomaly)
    logger.info(f"Proxy starting | upstream={upstream} | {host}:{port}")
    await run_proxy_server(proxy, upstream_url=upstream, host=host, port=port)

if __name__ == "__main__":
    asyncio.run(main())