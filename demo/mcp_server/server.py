"""
Demo MCP Server: Financial Assistant
Exposes financial tools that an AI agent might call.
Runs as a plain HTTP JSON-RPC server - no MCP SDK dependency needed for the demo.

Tools exposed:
  account_balance    - read account balance
  transaction_list   - list recent transactions
  transaction_summary - summarize transactions
  account_search     - search all accounts (sensitive - should be restricted)
  transfer_funds     - move money between accounts (high risk - blocked)
  export_all_data    - export full customer dataset (always blocked)
  code_execute       - run arbitrary code (always blocked)
"""

import json
import random
import time
import logging
from aiohttp import web

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MCP-SERVER] %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger(__name__)

# Fake data
ACCOUNTS = {
    "acc-001": {"owner": "alice@example.com", "balance": 12450.00, "currency": "USD"},
    "acc-002": {"owner": "bob@example.com",   "balance": 3200.50,  "currency": "USD"},
    "acc-003": {"owner": "carol@example.com", "balance": 87000.00, "currency": "USD"},
}

TRANSACTIONS = {
    "acc-001": [
        {"id": "tx-1", "amount": -45.00, "desc": "Coffee shop",    "date": "2026-03-28"},
        {"id": "tx-2", "amount": -120.00,"desc": "Grocery store",  "date": "2026-03-27"},
        {"id": "tx-3", "amount": 2500.00,"desc": "Salary deposit", "date": "2026-03-25"},
    ],
    "acc-002": [
        {"id": "tx-4", "amount": -800.00, "desc": "Rent",          "date": "2026-03-28"},
        {"id": "tx-5", "amount": 1500.00, "desc": "Freelance pay", "date": "2026-03-26"},
    ],
}

TOOL_SCHEMAS = [
    {
        "name": "account_balance",
        "description": "Get the balance for a specific account",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string", "description": "Account identifier"}
            },
            "required": ["account_id"]
        }
    },
    {
        "name": "transaction_list",
        "description": "List recent transactions for an account",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string"},
                "limit": {"type": "integer", "default": 10}
            },
            "required": ["account_id"]
        }
    },
    {
        "name": "transaction_summary",
        "description": "Summarize spending by category for an account",
        "inputSchema": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string"},
                "period_days": {"type": "integer", "default": 30}
            },
            "required": ["account_id"]
        }
    },
    {
        "name": "account_search",
        "description": "Search across all customer accounts - admin only",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 100}
            },
            "required": ["query"]
        }
    },
    {
        "name": "transfer_funds",
        "description": "Transfer funds between accounts",
        "inputSchema": {
            "type": "object",
            "properties": {
                "from_account": {"type": "string"},
                "to_account":   {"type": "string"},
                "amount":       {"type": "number"}
            },
            "required": ["from_account", "to_account", "amount"]
        }
    },
    {
        "name": "export_all_data",
        "description": "Export full customer dataset as CSV",
        "inputSchema": {"type": "object", "properties": {}}
    },
    {
        "name": "code_execute",
        "description": "Execute arbitrary Python code",
        "inputSchema": {
            "type": "object",
            "properties": {"code": {"type": "string"}},
            "required": ["code"]
        }
    },
]


def handle_tool(name: str, args: dict) -> dict:
    """Execute a tool call and return the result."""
    if name == "account_balance":
        acc = ACCOUNTS.get(args.get("account_id", ""))
        if not acc:
            return {"error": f"Account {args.get('account_id')} not found"}
        return {
            "account_id": args["account_id"],
            "balance": acc["balance"],
            "currency": acc["currency"],
            "as_of": "2026-03-29T12:00:00Z"
        }

    if name == "transaction_list":
        txns = TRANSACTIONS.get(args.get("account_id", ""), [])
        limit = args.get("limit", 10)
        return {"transactions": txns[:limit], "count": len(txns[:limit])}

    if name == "transaction_summary":
        txns = TRANSACTIONS.get(args.get("account_id", ""), [])
        total_in  = sum(t["amount"] for t in txns if t["amount"] > 0)
        total_out = sum(t["amount"] for t in txns if t["amount"] < 0)
        return {
            "period_days": args.get("period_days", 30),
            "total_income":  round(total_in, 2),
            "total_expenses": round(abs(total_out), 2),
            "net": round(total_in + total_out, 2),
            "transaction_count": len(txns)
        }

    if name == "account_search":
        # This tool REACHES THE SERVER only if mcp-authz allows it
        # (it shouldn't for a human_delegated_agent without admin scope)
        query = args.get("query", "").lower()
        results = [
            {"account_id": aid, **data}
            for aid, data in ACCOUNTS.items()
            if query in data["owner"].lower()
        ]
        return {"results": results, "count": len(results)}

    if name == "transfer_funds":
        # This should never reach here - mcp-authz blocks it
        return {
            "WARNING": "This tool reached the MCP server - mcp-authz did not block it!",
            "from": args.get("from_account"),
            "to":   args.get("to_account"),
            "amount": args.get("amount")
        }

    if name == "export_all_data":
        return {
            "WARNING": "This tool reached the MCP server - mcp-authz did not block it!",
            "data": list(ACCOUNTS.values())
        }

    if name == "code_execute":
        return {
            "WARNING": "This tool reached the MCP server - mcp-authz did not block it!",
            "code": args.get("code")
        }

    return {"error": f"Unknown tool: {name}"}


async def handle_jsonrpc(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        return web.Response(status=400, text='{"error":"invalid json"}',
                            content_type="application/json")

    method = body.get("method", "")
    req_id = body.get("id")

    # MCP initialize
    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "demo-financial-mcp", "version": "0.1.0"}
        }

    # MCP tools/list
    elif method == "tools/list":
        result = {"tools": TOOL_SCHEMAS}

    # MCP tools/call
    elif method == "tools/call":
        params   = body.get("params", {})
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})
        logger.info(f"TOOL CALL RECEIVED: {tool_name}({json.dumps(tool_args)})")
        tool_result = handle_tool(tool_name, tool_args)
        result = {
            "content": [{"type": "text", "text": json.dumps(tool_result, indent=2)}],
            "isError": "error" in tool_result or "WARNING" in tool_result
        }

    elif method == "notifications/initialized":
        return web.Response(status=204)

    else:
        result = None

    response_body = {"jsonrpc": "2.0", "id": req_id, "result": result}
    return web.Response(
        text=json.dumps(response_body),
        content_type="application/json"
    )


async def health(request: web.Request) -> web.Response:
    return web.Response(text='{"status":"ok","server":"demo-financial-mcp"}',
                        content_type="application/json")


def main():
    app = web.Application()
    app.router.add_post("/", handle_jsonrpc)
    app.router.add_post("/mcp", handle_jsonrpc)
    app.router.add_get("/health", health)
    logger.info("Demo MCP server starting on :8080")
    logger.info("Tools: account_balance, transaction_list, transaction_summary,")
    logger.info("       account_search (restricted), transfer_funds (blocked),")
    logger.info("       export_all_data (blocked), code_execute (blocked)")
    web.run_app(app, host="0.0.0.0", port=8080, print=None)


if __name__ == "__main__":
    main()
