import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { PlaceTradeArgs, PlaceTradeResult, TradeRecord } from "@mcp-sec/shared";

const SERVER_URL = "http://localhost:3030/mcp";
const TOOL_NAME = "place_trade";

const $ = <T extends HTMLElement>(sel: string): T => {
  const el = document.querySelector(sel);
  if (!el) throw new Error(`missing element: ${sel}`);
  return el as T;
};

const statusEl = $<HTMLSpanElement>("#status");
const toolsEl = $<HTMLUListElement>("#tools");
const formEl = $<HTMLFormElement>("#trade-form");
const submitEl = $<HTMLButtonElement>("#submit");
const logEl = $<HTMLPreElement>("#log");
const tradesEl = $<HTMLOListElement>("#trades");

const sessionTrades: TradeRecord[] = [];

function setStatus(state: "pending" | "ok" | "err", text: string): void {
  statusEl.className = `status status--${state}`;
  statusEl.textContent = text;
}

function log(line: string, kind: "info" | "ok" | "err" = "info"): void {
  const ts = new Date().toISOString().slice(11, 23);
  const span = document.createElement("span");
  if (kind !== "info") span.className = kind;
  span.textContent = `[${ts}] ${line}\n`;
  logEl.appendChild(span);
  logEl.scrollTop = logEl.scrollHeight;
}

function renderTrades(): void {
  if (sessionTrades.length === 0) {
    tradesEl.innerHTML = `<li class="muted">none yet</li>`;
    return;
  }
  tradesEl.innerHTML = "";
  for (const t of sessionTrades) {
    const li = document.createElement("li");
    li.textContent = `${t.executedAt}  ${t.side} ${t.quantity} ${t.symbol} @ ${t.limit}  →  ${t.tradeId}`;
    tradesEl.appendChild(li);
  }
}

async function connect(): Promise<Client> {
  const transport = new StreamableHTTPClientTransport(new URL(SERVER_URL));
  const client = new Client({ name: "mcp-sec-client", version: "0.0.0" });
  await client.connect(transport);
  return client;
}

async function main(): Promise<void> {
  setStatus("pending", "connecting…");
  let client: Client;
  try {
    client = await connect();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    setStatus("err", "disconnected");
    log(`connection failed: ${msg}`, "err");
    log(`is the server running on ${SERVER_URL}?`, "err");
    toolsEl.innerHTML = `<li class="muted">unavailable</li>`;
    return;
  }
  setStatus("ok", "connected");
  log("connected");

  let toolNames: string[] = [];
  try {
    const { tools } = await client.listTools();
    toolNames = tools.map((t) => t.name);
    toolsEl.innerHTML = "";
    for (const t of tools) {
      const li = document.createElement("li");
      li.textContent = `${t.name} — ${t.description ?? ""}`;
      toolsEl.appendChild(li);
    }
    log(`listed ${tools.length} tool(s)`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log(`listTools failed: ${msg}`, "err");
    return;
  }

  if (!toolNames.includes(TOOL_NAME)) {
    log(`server does not expose ${TOOL_NAME}; form disabled`, "err");
    return;
  }

  submitEl.disabled = false;

  formEl.addEventListener("submit", async (e) => {
    e.preventDefault();
    submitEl.disabled = true;
    try {
      const data = new FormData(formEl);
      const args: PlaceTradeArgs = {
        symbol: String(data.get("symbol") ?? "").trim(),
        side: data.get("side") === "sell" ? "sell" : "buy",
        quantity: Number(data.get("quantity")),
        limit: Number(data.get("limit")),
      };
      log(`call ${TOOL_NAME} ${JSON.stringify(args)}`);
      const res = await client.callTool({ name: TOOL_NAME, arguments: args });
      if (res.isError) {
        const text = Array.isArray(res.content) && res.content[0] && "text" in res.content[0]
          ? String(res.content[0].text)
          : "tool returned isError";
        log(`error: ${text}`, "err");
        return;
      }
      const structured = res.structuredContent as PlaceTradeResult | undefined;
      if (!structured || structured.success !== true) {
        log(`unexpected response: ${JSON.stringify(res)}`, "err");
        return;
      }
      log(`ok  tradeId=${structured.tradeId}  executedAt=${structured.executedAt}`, "ok");
      sessionTrades.push({ ...args, tradeId: structured.tradeId, executedAt: structured.executedAt });
      renderTrades();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log(`callTool failed: ${msg}`, "err");
    } finally {
      submitEl.disabled = false;
    }
  });
}

void main();
