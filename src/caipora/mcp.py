"""MCP mínimo, sem dependências: cliente (stdio e HTTP) e servidor stdio.

Cobre só o necessário para a caipora: initialize, tools/list e tools/call.
"""

from __future__ import annotations

import asyncio
import json
import shlex
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TextIO

import httpx

from . import __version__

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
CLIENT_INFO = {"name": "caipora", "version": __version__}


class McpError(Exception):
    pass


@dataclass
class McpTool:
    name: str
    description: str = ""
    input_schema: dict = field(default_factory=dict)
    annotations: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> McpTool:
        return cls(
            name=str(d.get("name", "")),
            description=str(d.get("description") or ""),
            input_schema=d.get("inputSchema") or {},
            annotations=d.get("annotations") or {},
        )


def tool_result_text(result: dict) -> str:
    parts = []
    for item in result.get("content", []):
        if item.get("type") == "text":
            parts.append(item.get("text", ""))
        else:
            parts.append(json.dumps(item, ensure_ascii=False))
    return "\n".join(parts)


class _BaseClient:
    def __init__(self) -> None:
        self._next_id = 0
        self.server_info: dict = {}
        self.protocol_version = PROTOCOL_VERSION

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    async def request(self, method: str, params: dict | None = None) -> dict:
        raise NotImplementedError

    async def notify(self, method: str, params: dict | None = None) -> None:
        raise NotImplementedError

    async def initialize(self) -> dict:
        result = await self.request(
            "initialize",
            {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO},
        )
        self.server_info = result.get("serverInfo", {})
        self.protocol_version = result.get("protocolVersion", PROTOCOL_VERSION)
        await self.notify("notifications/initialized")
        return result

    async def list_tools(self) -> list[McpTool]:
        tools: list[McpTool] = []
        cursor = None
        for _ in range(100):  # limite de páginas, contra servidor que nunca termina
            result = await self.request("tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(McpTool.from_dict(t) for t in result.get("tools", []))
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools

    async def call_tool(self, name: str, arguments: dict) -> dict:
        return await self.request("tools/call", {"name": name, "arguments": arguments})

    async def aclose(self) -> None:
        pass

    async def __aenter__(self):
        await self.initialize()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()


def _unwrap(message: dict) -> dict:
    if "error" in message:
        err = message["error"]
        raise McpError(f"{err.get('code')}: {err.get('message')}")
    return message.get("result", {})


class StdioClient(_BaseClient):
    """Sobe o servidor como subprocesso e fala JSON-RPC por linhas no stdin/stdout."""

    def __init__(self, command: str, timeout: float = 30.0) -> None:
        super().__init__()
        self.command = command
        self.timeout = timeout
        self._proc: asyncio.subprocess.Process | None = None

    async def initialize(self) -> dict:
        argv = shlex.split(self.command)
        if not argv:
            raise McpError("comando vazio")
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, limit=16 * 1024 * 1024
            )
        except FileNotFoundError as exc:
            raise McpError(f"comando não encontrado: {argv[0]}") from exc
        return await super().initialize()

    async def _write(self, message: dict) -> None:
        assert self._proc and self._proc.stdin
        self._proc.stdin.write((json.dumps(message, ensure_ascii=False) + "\n").encode())
        await self._proc.stdin.drain()

    async def notify(self, method: str, params: dict | None = None) -> None:
        await self._write({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})})

    async def request(self, method: str, params: dict | None = None) -> dict:
        assert self._proc and self._proc.stdout
        id_ = self._id()
        await self._write({"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}})

        async def read() -> dict:
            while True:
                line = await self._proc.stdout.readline()
                if not line:
                    raise McpError(f"o servidor encerrou antes de responder a '{method}'")
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue  # servidor imprimindo log no stdout
                if message.get("id") == id_ and ("result" in message or "error" in message):
                    return message

        try:
            message = await asyncio.wait_for(read(), self.timeout)
        except TimeoutError as exc:
            raise McpError(f"sem resposta para '{method}' em {self.timeout:.0f}s") from exc
        return _unwrap(message)

    async def aclose(self) -> None:
        if self._proc and self._proc.returncode is None:
            if self._proc.stdin:
                self._proc.stdin.close()
            try:
                await asyncio.wait_for(self._proc.wait(), 3)
            except TimeoutError:
                self._proc.kill()
                await self._proc.wait()


def _parse_sse(text: str) -> list[dict]:
    messages, data = [], []
    for line in text.splitlines() + [""]:
        if line.startswith("data:"):
            data.append(line[5:].lstrip())
        elif not line.strip() and data:
            try:
                messages.append(json.loads("\n".join(data)))
            except json.JSONDecodeError:
                pass
            data = []
    return messages


class HttpClient(_BaseClient):
    """Transporte "streamable HTTP": POST com JSON-RPC; resposta em JSON ou SSE."""

    def __init__(self, url: str, headers: dict[str, str] | None = None, timeout: float = 30.0, client: httpx.AsyncClient | None = None) -> None:
        super().__init__()
        self.url = url
        self._session_id: str | None = None
        self._initialized = False
        self._client = client or httpx.AsyncClient(timeout=timeout, headers=headers or {})

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        if self._session_id:
            h["Mcp-Session-Id"] = self._session_id
        if self._initialized:
            h["MCP-Protocol-Version"] = self.protocol_version
        return h

    async def _post(self, message: dict) -> httpx.Response:
        response = await self._client.post(self.url, json=message, headers=self._headers())
        if sid := response.headers.get("mcp-session-id"):
            self._session_id = sid
        if response.status_code >= 400:
            raise McpError(f"HTTP {response.status_code} em '{message.get('method')}': {response.text[:200]}")
        return response

    async def notify(self, method: str, params: dict | None = None) -> None:
        await self._post({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})})

    async def request(self, method: str, params: dict | None = None) -> dict:
        id_ = self._id()
        response = await self._post({"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}})
        if "text/event-stream" in response.headers.get("content-type", ""):
            candidates = _parse_sse(response.text)
        else:
            body = response.json()
            candidates = body if isinstance(body, list) else [body]
        for message in candidates:
            if message.get("id") == id_:
                return _unwrap(message)
        raise McpError(f"resposta para '{method}' não encontrada")

    async def initialize(self) -> dict:
        result = await super().initialize()
        self._initialized = True
        return result

    async def aclose(self) -> None:
        await self._client.aclose()


def connect(spec: str, headers: dict[str, str] | None = None, timeout: float = 30.0) -> _BaseClient:
    """URL http(s) usa o transporte HTTP; qualquer outra coisa é um comando que sobe um servidor stdio."""
    if spec.startswith(("http://", "https://")):
        return HttpClient(spec, headers=headers, timeout=timeout)
    return StdioClient(spec, timeout=timeout)


# ───────────────────────── servidor ─────────────────────────


@dataclass
class ServerTool:
    name: str
    description: str
    input_schema: dict
    handler: Callable[[dict], str]
    annotations: dict = field(default_factory=dict)


def handle_message(message: dict, tools: dict[str, ServerTool], server_name: str) -> dict | None:
    """Processa uma mensagem JSON-RPC e devolve a resposta (ou None para notificações)."""
    method = message.get("method")
    id_ = message.get("id")
    if id_ is None:
        return None
    params = message.get("params") or {}

    def ok(result: Any) -> dict:
        return {"jsonrpc": "2.0", "id": id_, "result": result}

    def err(code: int, text: str) -> dict:
        return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": text}}

    if method == "initialize":
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_VERSIONS else PROTOCOL_VERSION
        return ok({"protocolVersion": version, "capabilities": {"tools": {}}, "serverInfo": {"name": server_name, "version": __version__}})
    if method == "ping":
        return ok({})
    if method == "tools/list":
        listed = []
        for t in tools.values():
            item = {"name": t.name, "description": t.description, "inputSchema": t.input_schema}
            if t.annotations:
                item["annotations"] = t.annotations
            listed.append(item)
        return ok({"tools": listed})
    if method == "tools/call":
        tool = tools.get(params.get("name", ""))
        if tool is None:
            return err(-32602, f"ferramenta desconhecida: {params.get('name')}")
        try:
            text = tool.handler(params.get("arguments") or {})
        except Exception as exc:  # erro da ferramenta vira resultado com isError, como manda o protocolo
            return ok({"content": [{"type": "text", "text": str(exc)}], "isError": True})
        return ok({"content": [{"type": "text", "text": text}], "isError": False})
    return err(-32601, f"método não suportado: {method}")


def serve_stdio(tools: list[ServerTool], server_name: str, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> None:
    by_name = {t.name: t for t in tools}
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            reply: dict | None = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "JSON inválido"}}
        else:
            reply = handle_message(message, by_name, server_name) if isinstance(message, dict) else None
        if reply is not None:
            stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            stdout.flush()


def serve_honeypot(log_path: str | None) -> None:
    """Expõe as ferramentas do honeypot via MCP, registrando cada chamada no log."""
    from pathlib import Path

    from .honeypot import TOOLS, append_log
    from .types import ToolCall

    log = Path(log_path) if log_path else None

    def wrap(tool):
        def handler(args: dict) -> str:
            if log:
                append_log(log, ToolCall(tool.name, args, tool.dangerous))
            return tool.handler(args)

        return handler

    server_tools = [
        ServerTool(
            t.name,
            t.description,
            t.parameters,
            wrap(t),
            {"destructiveHint": True, "readOnlyHint": False} if t.dangerous else {"readOnlyHint": True},
        )
        for t in TOOLS
    ]
    serve_stdio(server_tools, "caipora-honeypot")
