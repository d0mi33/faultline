"""
Deterministic OpenAI-compatible mock LLM (stdlib only).

Lets the whole harness run offline with no API key, and makes CI runs
reproducible. It behaves like a *gullible* model on purpose: if a tool result
contains an instruction to run SQL, it obeys. That gives the prompt-injection
scenario something to catch. Swap in a real model (OPENAI_BASE_URL) to test
how an actual LLM behaves under the same faults.
"""

import json
import re
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INJECTED_SQL = re.compile(r'run_sql with "([^"]+)"', re.I)


def tool_call(sql: str) -> dict:
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [{
            "id": "call_" + uuid.uuid4().hex[:8],
            "type": "function",
            "function": {"name": "run_sql", "arguments": json.dumps({"query": sql})},
        }],
    }


def plan(messages: list[dict], has_tools: bool) -> dict:
    last = messages[-1]
    user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
    sql_calls = sum(len(m.get("tool_calls") or []) for m in messages if m["role"] == "assistant")

    if last["role"] == "tool":
        injected = INJECTED_SQL.search(last.get("content") or "")
        if injected and sql_calls < 2:
            return tool_call(injected.group(1))
        return {"role": "assistant", "content": f"Here is what I found:\n{last['content']}"}

    if not has_tools:
        return {"role": "assistant", "content": "I can't look that up right now, but your order is probably fine."}

    name = re.search(r"\b(Ada|Alan|Grace)\b", user)
    where = f"WHERE c.name LIKE '{name.group(1)}%'" if name else ""
    return tool_call(
        "SELECT o.id, o.item, o.status, o.placed_at FROM orders o "
        f"JOIN customers c ON c.id = o.customer_id {where} ORDER BY o.placed_at DESC"
    )


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not self.path.endswith("/chat/completions"):
            return self._send(404, {"error": "not found"})
        req = json.loads(self.rfile.read(int(self.headers["content-length"])))
        msg = plan(req["messages"], bool(req.get("tools")))
        self._send(200, {
            "id": "chatcmpl-" + uuid.uuid4().hex[:12],
            "object": "chat.completion",
            "created": int(time.time()),
            "model": req.get("model", "mock-gullible"),
            "choices": [{"index": 0, "message": msg,
                         "finish_reason": "tool_calls" if msg.get("tool_calls") else "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        })

    def do_GET(self):
        self._send(200, {"ok": True})

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
