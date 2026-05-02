import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import {
  EXPECTED_ORIGIN,
  RP_ID,
  RP_NAME,
  USER_DISPLAY_NAME,
  USER_HANDLE,
  USER_NAME,
  type PlaceTradeArgs,
  type PlaceTradeResult,
  type TradeRecord,
} from "@mcp-sec/shared";
import {
  APPROVAL_CHALLENGE_CREATE_METHOD,
  APPROVAL_ENROLL_BEGIN_METHOD,
  APPROVAL_ENROLL_FINISH_METHOD,
  ApprovalEvidenceSchema,
  VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM,
  VERIFIED_APPROVAL_REQUEST_META_KEY,
  VERIFIED_APPROVAL_REQUIRED,
  VERIFIED_APPROVAL_TOOL_META_KEY,
  type VerifiedApprovalToolMeta,
} from "mcp-verified-approval/shared";
import {
  createApprovalGate,
  createInMemoryCredentialStore,
  getApprovalCapabilityDeclaration,
  type ApprovalGate,
} from "mcp-verified-approval/server";

const PORT = 3030;
const ALLOWED_ORIGIN = "http://localhost:5173";
const SERVER_ID = "phase-3-dev-server";

const trades: TradeRecord[] = [];

// === Demo tool registry ====================================================
//
// The demo's tool registry maps a tool name to its full execution surface:
// the JSON inputSchema for tools/list, the zod argsSchema for runtime
// validation, the describe lambda the gate uses for displayText, and the
// execute lambda. The gate's own minimal registry (name -> {meta, describe})
// is populated by registerTool() below.

const PlaceTradeArgsSchema = z.object({
  symbol: z.string().min(1),
  side: z.enum(["buy", "sell"]),
  quantity: z.number().positive(),
  limit: z.number().positive(),
});

function executeTrade(args: PlaceTradeArgs): PlaceTradeResult {
  const record: TradeRecord = {
    ...args,
    tradeId: randomUUID(),
    executedAt: new Date().toISOString(),
  };
  trades.push(record);
  console.log(
    `[trade] ${record.executedAt} ${record.side} ${record.quantity} ${record.symbol} @ ${record.limit} -> ${record.tradeId}`,
  );
  return { success: true, tradeId: record.tradeId, executedAt: record.executedAt };
}

function describeTrade(args: PlaceTradeArgs): string {
  return `${args.side === "buy" ? "Buy" : "Sell"} ${args.quantity} ${args.symbol} at $${args.limit}`;
}

type ToolListEntry = {
  name: string;
  title?: string;
  description?: string;
  inputSchema: Record<string, unknown>;
  _meta?: Record<string, unknown>;
};

type DemoTool = {
  listEntry: ToolListEntry;
  argsSchema: z.ZodType<unknown>;
  describe: (args: unknown) => string;
  execute: (args: unknown) => {
    content: Array<{ type: "text"; text: string }>;
    structuredContent: unknown;
  };
};

const placeTradeMeta: VerifiedApprovalToolMeta = {
  required: VERIFIED_APPROVAL_REQUIRED,
  authenticatorClass: VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM,
};

const DEMO_TOOLS = new Map<string, DemoTool>();

DEMO_TOOLS.set("place_trade", {
  listEntry: {
    name: "place_trade",
    title: "Place trade",
    description: "Place a limit order. Appends to the in-memory trade log and returns the trade id.",
    inputSchema: {
      type: "object",
      required: ["symbol", "side", "quantity", "limit"],
      additionalProperties: false,
      properties: {
        symbol: { type: "string", minLength: 1, description: "Ticker symbol, e.g. AAPL" },
        side: { type: "string", enum: ["buy", "sell"] },
        quantity: { type: "number", exclusiveMinimum: 0 },
        limit: { type: "number", exclusiveMinimum: 0, description: "Limit price" },
      },
    },
    _meta: { [VERIFIED_APPROVAL_TOOL_META_KEY]: placeTradeMeta },
  },
  argsSchema: PlaceTradeArgsSchema,
  describe: (args) => {
    const parsed = PlaceTradeArgsSchema.safeParse(args);
    return parsed.success ? describeTrade(parsed.data) : "place_trade with given arguments";
  },
  execute: (rawArgs) => {
    const parsed = PlaceTradeArgsSchema.parse(rawArgs);
    const result = executeTrade(parsed);
    return {
      content: [
        {
          type: "text",
          text: `Placed ${parsed.side} ${parsed.quantity} ${parsed.symbol} @ ${parsed.limit} (id ${result.tradeId})`,
        },
      ],
      structuredContent: result,
    };
  },
});

// === Approval gate =========================================================

const credentialStore = createInMemoryCredentialStore();

const approvalGate: ApprovalGate = createApprovalGate({
  rpId: RP_ID,
  rpName: RP_NAME,
  expectedOrigin: EXPECTED_ORIGIN,
  serverId: SERVER_ID,
  getUserHandle: async () => USER_HANDLE,
  getUserName: async () => USER_NAME,
  getUserDisplayName: async () => USER_DISPLAY_NAME,
  credentialStore,
});

// Register the demo's gated tools with the gate. The gate stores name +
// toolMeta + describe; the demo's full registry stores execute + schemas.
approvalGate.registerTool({
  name: "place_trade",
  toolMeta: placeTradeMeta,
  describe: DEMO_TOOLS.get("place_trade")!.describe,
});

// === MCP request schemas ===================================================

const ListToolsRequestSchema = z.object({
  method: z.literal("tools/list"),
  params: z.unknown().optional(),
});

const CallToolRequestSchema = z.object({
  method: z.literal("tools/call"),
  params: z.object({
    name: z.string(),
    arguments: z.record(z.string(), z.unknown()).optional(),
    _meta: z
      .object({
        [VERIFIED_APPROVAL_REQUEST_META_KEY]: ApprovalEvidenceSchema.optional(),
      })
      .passthrough()
      .optional(),
  }),
});

const ApprovalChallengeCreateRequestSchema = z.object({
  method: z.literal(APPROVAL_CHALLENGE_CREATE_METHOD),
  params: z.object({
    toolName: z.string(),
    arguments: z.record(z.string(), z.unknown()),
  }),
});

const EnrollBeginRequestSchema = z.object({
  method: z.literal(APPROVAL_ENROLL_BEGIN_METHOD),
  params: z.unknown().optional(),
});

const EnrollFinishRequestSchema = z.object({
  method: z.literal(APPROVAL_ENROLL_FINISH_METHOD),
  params: z.object({
    response: z.record(z.string(), z.unknown()),
  }),
});

// === MCP server wiring =====================================================

function buildMcpServer(): McpServer {
  const mcp = new McpServer(
    { name: "mcp-sec-server", version: "0.4.0" },
    { capabilities: { tools: {}, ...getApprovalCapabilityDeclaration() } },
  );
  const server = mcp.server;

  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: [...DEMO_TOOLS.values()].map((t) => t.listEntry),
  }));

  server.setRequestHandler(EnrollBeginRequestSchema, async () => {
    return await approvalGate.handleEnrollBegin();
  });

  server.setRequestHandler(EnrollFinishRequestSchema, async (req) => {
    return await approvalGate.handleEnrollFinish({ response: req.params.response });
  });

  server.setRequestHandler(ApprovalChallengeCreateRequestSchema, async (req) => {
    return await approvalGate.handleChallengeCreate(req.params);
  });

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs, _meta } = req.params;
    const tool = DEMO_TOOLS.get(name);
    if (!tool) throw new McpError(-32602, `Unknown tool: ${name}`);

    if (approvalGate.getToolApprovalMeta(name)?.required === VERIFIED_APPROVAL_REQUIRED) {
      const evidence = _meta?.[VERIFIED_APPROVAL_REQUEST_META_KEY];
      await approvalGate.verifyApprovalForCall(name, rawArgs, evidence);
    }

    try {
      return tool.execute(rawArgs);
    } catch (err) {
      if (err instanceof z.ZodError) {
        throw new McpError(-32602, `Invalid arguments: ${err.message}`);
      }
      throw err;
    }
  });

  return mcp;
}

// === HTTP wiring (unchanged from Phase 0/1/2/3) ============================

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

export function startServer(port: number = PORT): Promise<{ port: number; close: () => Promise<void> }> {
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
    if (req.method === "GET" && url === "/credentials") {
      const list = await credentialStore.list(USER_HANDLE);
      const out = list.map((c) => ({
        credentialId: c.credentialId,
        transports: c.transports,
        userHandle: c.userHandle,
        counter: c.counter,
        createdAt: c.createdAt,
      }));
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(out, null, 2));
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

  return new Promise((resolve) => {
    httpServer.listen(port, () => {
      const addr = httpServer.address();
      const boundPort = typeof addr === "object" && addr ? addr.port : port;
      resolve({
        port: boundPort,
        close: () =>
          new Promise<void>((res, rej) => {
            for (const t of transports.values()) void t.close();
            transports.clear();
            approvalGate.shutdown();
            httpServer.close((err) => (err ? rej(err) : res()));
          }),
      });
    });
  });
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const handle = await startServer(PORT);
  const annotated = [...DEMO_TOOLS.values()]
    .filter((t) => approvalGate.getToolApprovalMeta(t.listEntry.name)?.required === VERIFIED_APPROVAL_REQUIRED)
    .map((t) => {
      const meta = approvalGate.getToolApprovalMeta(t.listEntry.name)!;
      return `${t.listEntry.name}[${meta.authenticatorClass ?? "cross-platform"}]`;
    });
  console.log("──────────────────────────────────────────────");
  console.log(" mcp-sec server (Phase 4b)");
  console.log(` port:      ${handle.port}`);
  console.log(" transport: Streamable HTTP (stateful, /mcp)");
  console.log(` tools:     ${[...DEMO_TOOLS.keys()].join(", ")}  (verified-approval: ${annotated.join(", ") || "none"})`);
  console.log(
    ` methods:   ${APPROVAL_CHALLENGE_CREATE_METHOD}, ${APPROVAL_ENROLL_BEGIN_METHOD}, ${APPROVAL_ENROLL_FINISH_METHOD}, tools/list, tools/call`,
  );
  console.log(` rp:        id=${RP_ID}  origin=${EXPECTED_ORIGIN}  user=${USER_HANDLE}`);
  console.log(` debug:     GET http://localhost:${handle.port}/trades`);
  console.log(`            GET http://localhost:${handle.port}/credentials`);
  console.log(` cors:      ${ALLOWED_ORIGIN}`);
  console.log("──────────────────────────────────────────────");
}
