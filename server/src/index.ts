import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomUUID, webcrypto } from "node:crypto";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import {
  APPROVAL_CHALLENGE_CREATE_METHOD,
  APPROVAL_ERROR_CODE,
  VERIFIED_APPROVAL_META_KEY,
  VERIFIED_APPROVAL_VERIFIED,
  canonicalArgs,
  type ApprovalChallenge,
  type ApprovalErrorReason,
  type PlaceTradeArgs,
  type PlaceTradeResult,
  type TradeRecord,
} from "@mcp-sec/shared";

const PORT = 3030;
const ALLOWED_ORIGIN = "http://localhost:5173";
const TOOL_NAME = "place_trade";
const SERVER_ID = "phase-1-dev-server";
const CHALLENGE_TTL_MS = 60_000;
const REAPER_INTERVAL_MS = 30_000;

const trades: TradeRecord[] = [];

// === Pending approval challenges ===

type PendingChallenge = {
  toolName: string;
  canonicalArgsJson: string;
  actionHash: string;
  expiresAt: number;
  consumed: boolean;
};

const challenges = new Map<string, PendingChallenge>();

setInterval(() => {
  const now = Date.now();
  for (const [id, c] of challenges) {
    if (c.consumed || c.expiresAt <= now) challenges.delete(id);
  }
}, REAPER_INTERVAL_MS).unref();

async function computeActionHash(toolName: string, canonicalArgsJson: string): Promise<string> {
  const data = new TextEncoder().encode(`${toolName}\0${canonicalArgsJson}\0${SERVER_ID}`);
  const buf = await webcrypto.subtle.digest("SHA-256", data);
  return Buffer.from(buf).toString("hex");
}

function approvalError(reason: ApprovalErrorReason, message: string): McpError {
  return new McpError(APPROVAL_ERROR_CODE, message, { reason });
}

// === Trade tool ===

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

// === MCP request schemas ===

const ListToolsRequestSchema = z.object({
  method: z.literal("tools/list"),
  params: z.unknown().optional(),
});

const CallToolRequestSchema = z.object({
  method: z.literal("tools/call"),
  params: z
    .object({
      name: z.string(),
      arguments: z.record(z.string(), z.unknown()).optional(),
      approvalEvidence: z
        .object({
          method: z.literal("stub"),
          challengeId: z.string(),
          userConfirmed: z.literal(true),
        })
        .optional(),
    })
    .passthrough(),
});

const ApprovalChallengeCreateRequestSchema = z.object({
  method: z.literal(APPROVAL_CHALLENGE_CREATE_METHOD),
  params: z.object({
    toolName: z.string(),
    arguments: z.record(z.string(), z.unknown()),
  }),
});

// === Handlers ===

function describeTrade(args: PlaceTradeArgs): string {
  return `${args.side === "buy" ? "Buy" : "Sell"} ${args.quantity} ${args.symbol} at $${args.limit}`;
}

function buildMcpServer(): McpServer {
  // We bypass McpServer.registerTool because the brief puts approvalEvidence
  // at params.approvalEvidence (sibling of name/arguments), which the SDK's
  // built-in CallToolRequestSchema strips. Reaching through mcp.server with
  // a custom request schema lets us see the full params.
  const mcp = new McpServer(
    { name: "mcp-sec-server", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );
  const server = mcp.server;

  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: [
      {
        name: TOOL_NAME,
        title: "Place trade",
        description:
          "Place a limit order. Appends to the in-memory trade log and returns the trade id.",
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
        _meta: {
          [VERIFIED_APPROVAL_META_KEY]: VERIFIED_APPROVAL_VERIFIED,
        },
      },
    ],
  }));

  server.setRequestHandler(ApprovalChallengeCreateRequestSchema, async (req): Promise<ApprovalChallenge> => {
    const { toolName, arguments: args } = req.params;
    if (toolName !== TOOL_NAME) {
      throw new McpError(-32602, `Unknown tool: ${toolName}`);
    }
    // We canonicalize whatever arguments were sent — they're not validated
    // against the tool's schema yet (that happens at tools/call). The hash
    // commits the server to *exactly* these bytes; if the eventual call
    // sends anything different, hash comparison fails.
    const canonicalArgsJson = canonicalArgs(args);
    const actionHash = await computeActionHash(toolName, canonicalArgsJson);
    const challengeId = randomUUID();
    const nonce = randomUUID();
    const expiresAtMs = Date.now() + CHALLENGE_TTL_MS;
    challenges.set(challengeId, {
      toolName,
      canonicalArgsJson,
      actionHash,
      expiresAt: expiresAtMs,
      consumed: false,
    });

    const parsedArgs = PlaceTradeArgsSchema.safeParse(args);
    const displayText = parsedArgs.success
      ? describeTrade(parsedArgs.data)
      : `${toolName} with given arguments`;

    console.log(`[approval] challenge ${challengeId} for ${toolName} (${displayText})`);
    return {
      challengeId,
      nonce,
      actionHash,
      displayText,
      expiresAt: new Date(expiresAtMs).toISOString(),
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs, approvalEvidence } = req.params;
    if (name !== TOOL_NAME) {
      throw new McpError(-32602, `Unknown tool: ${name}`);
    }

    if (!approvalEvidence) {
      throw approvalError("missing_evidence", "Approval evidence required");
    }
    const stored = challenges.get(approvalEvidence.challengeId);
    const now = Date.now();
    if (!stored || stored.consumed || stored.expiresAt <= now || stored.toolName !== name) {
      throw approvalError("invalid_challenge", "Invalid or expired approval challenge");
    }

    const callCanonical = canonicalArgs(rawArgs ?? {});
    const callHash = await computeActionHash(name, callCanonical);
    if (callHash !== stored.actionHash) {
      throw approvalError(
        "argument_hash_mismatch",
        "Approval challenge was issued for different arguments",
      );
    }

    // Atomic consume: Node is single-threaded so this check-and-set cannot be
    // interrupted within one event-loop tick. Phase 4 may extract this into a
    // multi-process server — at that point this needs a real CAS (DB row lock,
    // Redis SETNX, etc.) so two workers can't both consume the same challenge.
    if (stored.consumed) {
      throw approvalError("invalid_challenge", "Approval challenge already consumed");
    }
    stored.consumed = true;

    const parsed = PlaceTradeArgsSchema.safeParse(rawArgs);
    if (!parsed.success) {
      throw new McpError(-32602, `Invalid arguments: ${parsed.error.message}`);
    }
    const result = executeTrade(parsed.data);
    return {
      content: [
        {
          type: "text",
          text: `Placed ${parsed.data.side} ${parsed.data.quantity} ${parsed.data.symbol} @ ${parsed.data.limit} (id ${result.tradeId})`,
        },
      ],
      structuredContent: result,
    };
  });

  return mcp;
}

// === HTTP wiring (unchanged from Phase 0) ===

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
            httpServer.close((err) => (err ? rej(err) : res()));
          }),
      });
    });
  });
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  const handle = await startServer(PORT);
  console.log("──────────────────────────────────────────────");
  console.log(" mcp-sec server (Phase 1)");
  console.log(` port:      ${handle.port}`);
  console.log(" transport: Streamable HTTP (stateful, /mcp)");
  console.log(` tools:     ${TOOL_NAME}  [${VERIFIED_APPROVAL_META_KEY}=${VERIFIED_APPROVAL_VERIFIED}]`);
  console.log(` methods:   ${APPROVAL_CHALLENGE_CREATE_METHOD}, tools/list, tools/call`);
  console.log(` debug:     GET http://localhost:${handle.port}/trades`);
  console.log(` cors:      ${ALLOWED_ORIGIN}`);
  console.log("──────────────────────────────────────────────");
}
