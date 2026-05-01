import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { TradeRecord, PlaceTradeResult } from "@mcp-sec/shared";

const PORT = 3030;
const ALLOWED_ORIGIN = "http://localhost:5173";
const TOOL_NAME = "place_trade";

const trades: TradeRecord[] = [];

function buildMcpServer(): McpServer {
  const server = new McpServer({
    name: "mcp-sec-server",
    version: "0.0.0",
  });

  server.registerTool(
    TOOL_NAME,
    {
      title: "Place trade",
      description:
        "Place a limit order. Appends to the in-memory trade log and returns the trade id. Phase 0: no approval, no auth.",
      inputSchema: {
        symbol: z.string().min(1).describe("Ticker symbol, e.g. AAPL"),
        side: z.enum(["buy", "sell"]),
        quantity: z.number().positive(),
        limit: z.number().positive().describe("Limit price in account currency"),
      },
    },
    async ({ symbol, side, quantity, limit }) => {
      const record: TradeRecord = {
        symbol,
        side,
        quantity,
        limit,
        tradeId: randomUUID(),
        executedAt: new Date().toISOString(),
      };
      trades.push(record);
      console.log(
        `[trade] ${record.executedAt} ${record.side} ${record.quantity} ${record.symbol} @ ${record.limit} -> ${record.tradeId}`,
      );
      const result: PlaceTradeResult = {
        success: true,
        tradeId: record.tradeId,
        executedAt: record.executedAt,
      };
      return {
        content: [
          {
            type: "text",
            text: `Placed ${record.side} ${record.quantity} ${record.symbol} @ ${record.limit} (id ${record.tradeId})`,
          },
        ],
        structuredContent: result,
      };
    },
  );

  return server;
}

function setCorsHeaders(res: ServerResponse): void {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "content-type, mcp-session-id, mcp-protocol-version, last-event-id, authorization",
  );
  res.setHeader("Access-Control-Expose-Headers", "mcp-session-id");
}

const transports = new Map<string, StreamableHTTPServerTransport>();

async function getOrCreateTransport(
  sessionId: string | undefined,
): Promise<StreamableHTTPServerTransport> {
  if (sessionId !== undefined) {
    const existing = transports.get(sessionId);
    if (existing) return existing;
  }
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    onsessioninitialized: (sid) => {
      transports.set(sid, transport);
      console.log(`[mcp] session initialized: ${sid}`);
    },
  });
  transport.onclose = () => {
    if (transport.sessionId) {
      transports.delete(transport.sessionId);
      console.log(`[mcp] session closed: ${transport.sessionId}`);
    }
  };
  const mcp = buildMcpServer();
  await mcp.connect(transport);
  return transport;
}

const httpServer = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  setCorsHeaders(res);

  if (req.method === "OPTIONS") {
    res.writeHead(204).end();
    return;
  }

  const url = req.url ?? "/";

  if (req.method === "GET" && url === "/trades") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(trades, null, 2));
    return;
  }

  if (url === "/mcp" || url.startsWith("/mcp?")) {
    try {
      const headerSessionId = req.headers["mcp-session-id"];
      const sessionId = Array.isArray(headerSessionId) ? headerSessionId[0] : headerSessionId;
      const transport = await getOrCreateTransport(sessionId);
      await transport.handleRequest(req, res);
    } catch (err) {
      console.error("[mcp] request error:", err);
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "internal" }));
      }
    }
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "not found" }));
});

httpServer.listen(PORT, () => {
  console.log("──────────────────────────────────────────────");
  console.log(" mcp-sec server (Phase 0)");
  console.log(` port:      ${PORT}`);
  console.log(" transport: Streamable HTTP (stateful, /mcp)");
  console.log(` tools:     ${TOOL_NAME}`);
  console.log(` debug:     GET http://localhost:${PORT}/trades`);
  console.log(` cors:      ${ALLOWED_ORIGIN}`);
  console.log("──────────────────────────────────────────────");
});
