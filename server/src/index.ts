import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomBytes, randomUUID, webcrypto } from "node:crypto";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import {
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  RegistrationResponseJSON,
  WebAuthnCredential,
} from "@simplewebauthn/server";
import {
  APPROVAL_CHALLENGE_CREATE_METHOD,
  APPROVAL_ENROLL_BEGIN_METHOD,
  APPROVAL_ENROLL_FINISH_METHOD,
  APPROVAL_ERROR_CODE,
  EXPECTED_ORIGIN,
  RP_ID,
  RP_NAME,
  USER_DISPLAY_NAME,
  USER_HANDLE,
  USER_NAME,
  VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM,
  VERIFIED_APPROVAL_META_KEY,
  VERIFIED_APPROVAL_REQUIRED,
  canonicalArgs,
  policyAcceptsTransports,
  type ApprovalChallenge,
  type ApprovalErrorReason,
  type PlaceTradeArgs,
  type PlaceTradeResult,
  type PublicKeyCredentialRequestOptionsJSONShape,
  type TradeRecord,
  type VerifiedApprovalAuthenticatorClass,
  type VerifiedApprovalToolMeta,
} from "@mcp-sec/shared";

const PORT = 3030;
const ALLOWED_ORIGIN = "http://localhost:5173";
const SERVER_ID = "phase-3-dev-server";
const CHALLENGE_TTL_MS = 60_000;
const REAPER_INTERVAL_MS = 30_000;
// WebAuthn registration with hybrid transport (Mac shows QR, iPhone scans)
// reliably takes 30-90s. Five minutes leaves headroom for hesitation.
const ENROLL_CHALLENGE_TTL_MS = 5 * 60_000;
const ENROLL_TIMEOUT_MS = 5 * 60_000;
const ASSERT_TIMEOUT_MS = 60_000;

const trades: TradeRecord[] = [];

function approvalError(reason: ApprovalErrorReason, message: string): McpError {
  return new McpError(APPROVAL_ERROR_CODE, message, { reason });
}

// === Pending approval challenges ===

type PendingChallenge = {
  toolName: string;
  canonicalArgsJson: string;
  actionHash: string;        // hex SHA-256
  nonceBase64Url: string;    // 32 bytes random
  wireChallenge: string;     // base64url(nonce || actionHashBytes); what the authenticator signs
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

async function computeActionHashHex(toolName: string, canonicalArgsJson: string): Promise<string> {
  const data = new TextEncoder().encode(`${toolName}\0${canonicalArgsJson}\0${SERVER_ID}`);
  const buf = await webcrypto.subtle.digest("SHA-256", data);
  return Buffer.from(buf).toString("hex");
}

// === Enrolled WebAuthn credentials ===

type CredentialRecord = {
  credentialId: string;
  // Pin to the SDK's exact public-key type so the registration assignment
  // and verify-call passing line up by construction. (TS otherwise narrows
  // `Uint8Array` to `Uint8Array<ArrayBuffer>`, which is too strict for the
  // `Uint8Array<ArrayBufferLike>` the SDK returns.)
  publicKey: WebAuthnCredential["publicKey"];
  counter: number;
  transports?: AuthenticatorTransportFuture[];
  userHandle: string;
  createdAt: string;
};

const credentials = new Map<string, CredentialRecord>();

const pendingEnrollments = new Map<string, { challenge: string; expiresAt: number }>();

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of pendingEnrollments) {
    if (v.expiresAt <= now) pendingEnrollments.delete(k);
  }
}, REAPER_INTERVAL_MS).unref();

const userHandleBytes = new TextEncoder().encode(USER_HANDLE);

// === Tool registry ===
//
// Single registered tool today. The registry exists so that the approval gate
// can read each tool's _meta.verifiedApproval centrally — the Phase 1
// hardcoded tool-name branch went away in Phase 3 (verification/phase-1.md
// Finding 5 carry-forward). Adding a second annotated tool is now a one-line
// operation: push to TOOLS, point at its arg schema and execute() lambda.

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

type RegisteredTool = {
  listEntry: ToolListEntry;
  toolMeta?: VerifiedApprovalToolMeta;
  argsSchema: z.ZodType<unknown>;
  describe: (args: unknown) => string;
  execute: (args: unknown) => {
    content: Array<{ type: "text"; text: string }>;
    structuredContent: unknown;
  };
};

const TOOLS = new Map<string, RegisteredTool>();

const placeTradeMeta: VerifiedApprovalToolMeta = {
  required: VERIFIED_APPROVAL_REQUIRED,
  authenticatorClass: VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM,
};

TOOLS.set("place_trade", {
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
    _meta: { [VERIFIED_APPROVAL_META_KEY]: placeTradeMeta },
  },
  toolMeta: placeTradeMeta,
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

// === MCP request schemas ===

const ListToolsRequestSchema = z.object({
  method: z.literal("tools/list"),
  params: z.unknown().optional(),
});

// Single-variant today; switch to z.discriminatedUnion when a second
// evidence method (delegated session, hardware token, …) materializes.
const ApprovalEvidenceSchema = z.object({
  method: z.literal("webauthn"),
  challengeId: z.string(),
  response: z.record(z.string(), z.unknown()),
});

const CallToolRequestSchema = z.object({
  method: z.literal("tools/call"),
  params: z.object({
    name: z.string(),
    arguments: z.record(z.string(), z.unknown()).optional(),
    _meta: z
      .object({
        [VERIFIED_APPROVAL_META_KEY]: ApprovalEvidenceSchema.optional(),
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

// === Handlers ===

async function handleChallengeCreate(
  toolName: string,
  args: Record<string, unknown>,
): Promise<ApprovalChallenge> {
  const tool = TOOLS.get(toolName);
  if (!tool) {
    throw new McpError(-32602, `Unknown tool: ${toolName}`);
  }
  if (tool.toolMeta?.required !== VERIFIED_APPROVAL_REQUIRED) {
    throw new McpError(-32602, `Tool ${toolName} does not require verified approval`);
  }

  const policy: VerifiedApprovalAuthenticatorClass =
    tool.toolMeta.authenticatorClass ?? VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM;

  const eligible = [...credentials.values()].filter(
    (c) => c.userHandle === USER_HANDLE && policyAcceptsTransports(policy, c.transports),
  );
  if (eligible.length === 0) {
    throw approvalError(
      "no_eligible_credential",
      `No enrolled credential satisfies the ${policy} authenticator-class policy for ${toolName}`,
    );
  }

  const canonicalArgsJson = canonicalArgs(args);
  const actionHashHex = await computeActionHashHex(toolName, canonicalArgsJson);
  const actionHashBytes = Buffer.from(actionHashHex, "hex");
  const nonceBytes = randomBytes(32);
  // Wire challenge: base64url(nonce || actionHash). The 32-byte nonce gives
  // freshness; the 32-byte actionHash binds this signature to the specific
  // canonicalized argument string. The server stores both halves and compares
  // them at verify time: the SDK's expectedChallenge check pins the wire
  // bytes, AND we recompute the action hash from the actual call args (defense
  // in depth — mismatch -> argument_hash_mismatch). See docs/DECISIONS.md for
  // the binding rationale and the byte-order specification.
  const wireChallengeBytes = Buffer.concat([nonceBytes, actionHashBytes]);
  const wireChallenge = wireChallengeBytes.toString("base64url");

  const challengeId = randomUUID();
  const expiresAtMs = Date.now() + CHALLENGE_TTL_MS;
  challenges.set(challengeId, {
    toolName,
    canonicalArgsJson,
    actionHash: actionHashHex,
    nonceBase64Url: nonceBytes.toString("base64url"),
    wireChallenge,
    expiresAt: expiresAtMs,
    consumed: false,
  });

  const requestOptions: PublicKeyCredentialRequestOptionsJSONShape = {
    challenge: wireChallenge,
    rpId: RP_ID,
    allowCredentials: eligible.map((c) => ({
      type: "public-key" as const,
      id: c.credentialId,
      transports: c.transports,
    })),
    userVerification: "required",
    timeout: ASSERT_TIMEOUT_MS,
    // Phase 4 mitigation 1 (investigation only): WebAuthn L3 hint to nudge
    // the OS picker toward the cross-device path for synced credentials
    // that advertise both `hybrid` and `internal`. Hints are advisory; the
    // platform may ignore them. Outcome of hardware testing decides whether
    // this stays.
    hints: ["hybrid"],
  };

  const displayText = tool.describe(args);
  console.log(
    `[approval] challenge ${challengeId} for ${toolName} (${displayText}); ${eligible.length} eligible cred(s) under policy=${policy}`,
  );
  return {
    challengeId,
    displayText,
    expiresAt: new Date(expiresAtMs).toISOString(),
    requestOptions,
  };
}

async function verifyAndConsume(
  tool: RegisteredTool,
  rawArgs: Record<string, unknown> | undefined,
  evidence: { challengeId: string; response: Record<string, unknown> },
): Promise<void> {
  // 1. Look up the pending challenge with split-reason precision.
  const stored = challenges.get(evidence.challengeId);
  if (!stored) throw approvalError("challenge_unknown", "Approval challenge not found");
  if (stored.consumed) throw approvalError("challenge_consumed", "Approval challenge already consumed");
  if (stored.expiresAt <= Date.now()) throw approvalError("challenge_expired", "Approval challenge expired");
  if (stored.toolName !== tool.listEntry.name) {
    throw approvalError("challenge_wrong_tool", "Approval challenge issued for a different tool");
  }

  // 2. Look up the credential.
  const responseId = String((evidence.response as { id?: unknown }).id ?? "");
  const cred = credentials.get(responseId);
  if (!cred) throw approvalError("unknown_credential", "Credential not enrolled");

  // 3. Authenticator-class policy. Filtered out at challenge issuance, but
  //    re-checked here as defense in depth: a malicious client could re-use a
  //    challenge created for one user with an ineligible credential they
  //    enrolled later, or forge an allowCredentials list, etc.
  const policy = tool.toolMeta?.authenticatorClass;
  if (!policyAcceptsTransports(policy, cred.transports)) {
    throw approvalError(
      "authenticator_class_mismatch",
      `Credential transports ${JSON.stringify(cred.transports ?? [])} do not satisfy ${policy ?? "cross-platform"} policy`,
    );
  }

  // 4. Verify the signature. SimpleWebAuthn enforces strictly-monotonic
  //    counter when stored counter > 0; we map that specific failure to
  //    signature_counter_regression and everything else to
  //    signature_verification_failed.
  const oldCounter = cred.counter;
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: evidence.response as unknown as AuthenticationResponseJSON,
      expectedChallenge: stored.wireChallenge,
      expectedOrigin: EXPECTED_ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: cred.credentialId,
        publicKey: cred.publicKey,
        counter: cred.counter,
        transports: cred.transports,
      },
      requireUserVerification: true,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (/counter/i.test(msg)) {
      throw approvalError("signature_counter_regression", `Signature counter did not increase: ${msg}`);
    }
    throw approvalError("signature_verification_failed", `Signature verification failed: ${msg}`);
  }
  if (!verification.verified) {
    throw approvalError("signature_verification_failed", "Signature did not verify");
  }

  // 5. Recompute the action hash from the actual call args. The wire
  //    challenge already encodes the action hash, so this is structurally
  //    redundant — but cheap, and defense in depth catches a class of bugs
  //    where someone constructs the wire challenge by re-using a previous
  //    server-issued one. If the args changed, the recomputed hash diverges.
  const callCanonical = canonicalArgs(rawArgs ?? {});
  const callHashHex = await computeActionHashHex(tool.listEntry.name, callCanonical);
  if (callHashHex !== stored.actionHash) {
    throw approvalError(
      "argument_hash_mismatch",
      "Approval evidence does not match the arguments of this call",
    );
  }

  // 6. Atomic consume. The check-and-set on these two lines happens in a
  //    single event-loop tick — synchronous, uninterruptible. The earlier
  //    consumed check (top of this function) can race because of the awaits
  //    above, but this late re-read catches it: by the time a second caller
  //    resumes from its own awaits, the first has already set consumed=true.
  //    In a multi-process server (Phase 4+ candidate) this needs a real CAS
  //    (DB row lock, Redis SETNX) so two workers can't both consume.
  if (stored.consumed) {
    throw approvalError("challenge_consumed", "Approval challenge already consumed (race)");
  }
  stored.consumed = true;

  // 7. Persist the new counter so a replay across sessions trips the counter
  //    check. Apple's synced passkeys often report counter 0 forever — that's
  //    spec-permitted and means the counter check isn't load-bearing for
  //    those credentials. (The challenge_consumed check is the freshness
  //    guarantee; counter is defense-in-depth against authenticator cloning.)
  cred.counter = verification.authenticationInfo.newCounter;
  console.log(
    `[approval] consumed ${evidence.challengeId} for ${tool.listEntry.name}; counter ${oldCounter} -> ${cred.counter}`,
  );
}

function buildMcpServer(): McpServer {
  const mcp = new McpServer(
    { name: "mcp-sec-server", version: "0.3.0" },
    { capabilities: { tools: {} } },
  );
  const server = mcp.server;

  server.setRequestHandler(ListToolsRequestSchema, () => ({
    tools: [...TOOLS.values()].map((t) => t.listEntry),
  }));

  server.setRequestHandler(EnrollBeginRequestSchema, async () => {
    const userHandle = USER_HANDLE;
    const exclude = [...credentials.values()]
      .filter((c) => c.userHandle === userHandle)
      .map((c) => ({ id: c.credentialId, transports: c.transports }));
    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: USER_NAME,
      userID: userHandleBytes,
      userDisplayName: USER_DISPLAY_NAME,
      attestationType: "none",
      excludeCredentials: exclude,
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
      timeout: ENROLL_TIMEOUT_MS,
    });
    pendingEnrollments.set(userHandle, {
      challenge: options.challenge,
      expiresAt: Date.now() + ENROLL_CHALLENGE_TTL_MS,
    });
    console.log(
      `[enroll] options issued for ${userHandle} (challenge ${options.challenge.slice(0, 8)}…, ${exclude.length} existing creds excluded)`,
    );
    return { options };
  });

  server.setRequestHandler(EnrollFinishRequestSchema, async (req) => {
    const userHandle = USER_HANDLE;
    const pending = pendingEnrollments.get(userHandle);
    if (!pending || pending.expiresAt <= Date.now()) {
      throw new McpError(APPROVAL_ERROR_CODE, "No pending enrollment or challenge expired", {
        reason: "no_pending_enrollment",
      });
    }
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: req.params.response as unknown as RegistrationResponseJSON,
        expectedChallenge: pending.challenge,
        expectedOrigin: EXPECTED_ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: false,
      });
    } catch (err) {
      pendingEnrollments.delete(userHandle);
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`[enroll] verification threw: ${msg}`);
      throw new McpError(APPROVAL_ERROR_CODE, `Registration verification failed: ${msg}`, {
        reason: "verification_failed",
      });
    }
    pendingEnrollments.delete(userHandle);
    if (!verification.verified || !verification.registrationInfo) {
      throw new McpError(APPROVAL_ERROR_CODE, "Registration not verified", {
        reason: "verification_failed",
      });
    }
    const { credential } = verification.registrationInfo;
    const record: CredentialRecord = {
      credentialId: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
      transports: credential.transports,
      userHandle,
      createdAt: new Date().toISOString(),
    };
    credentials.set(credential.id, record);
    console.log(
      `[enroll] credential stored: ${credential.id.slice(0, 12)}… (${credential.transports?.join(",") ?? "no transports"}) at ${record.createdAt}; total now ${credentials.size}`,
    );
    return {
      success: true,
      credentialId: credential.id,
      createdAt: record.createdAt,
    };
  });

  server.setRequestHandler(ApprovalChallengeCreateRequestSchema, async (req): Promise<ApprovalChallenge> => {
    return await handleChallengeCreate(req.params.toolName, req.params.arguments);
  });

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs, _meta } = req.params;
    const tool = TOOLS.get(name);
    if (!tool) throw new McpError(-32602, `Unknown tool: ${name}`);

    const requiresApproval = tool.toolMeta?.required === VERIFIED_APPROVAL_REQUIRED;
    if (requiresApproval) {
      const evidence = _meta?.[VERIFIED_APPROVAL_META_KEY];
      if (!evidence) throw approvalError("missing_evidence", "Approval evidence required");
      await verifyAndConsume(tool, rawArgs, evidence);
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

// === HTTP wiring (unchanged from Phase 0/1/2) ===

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
      const list = [...credentials.values()].map((c) => ({
        credentialId: c.credentialId,
        transports: c.transports,
        userHandle: c.userHandle,
        counter: c.counter,
        createdAt: c.createdAt,
      }));
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(list, null, 2));
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
  const annotated = [...TOOLS.values()]
    .filter((t) => t.toolMeta?.required === VERIFIED_APPROVAL_REQUIRED)
    .map((t) => `${t.listEntry.name}[${t.toolMeta?.authenticatorClass ?? "cross-platform"}]`);
  console.log("──────────────────────────────────────────────");
  console.log(" mcp-sec server (Phase 3)");
  console.log(` port:      ${handle.port}`);
  console.log(" transport: Streamable HTTP (stateful, /mcp)");
  console.log(` tools:     ${[...TOOLS.keys()].join(", ")}  (verified-approval: ${annotated.join(", ") || "none"})`);
  console.log(
    ` methods:   ${APPROVAL_CHALLENGE_CREATE_METHOD}, ${APPROVAL_ENROLL_BEGIN_METHOD}, ${APPROVAL_ENROLL_FINISH_METHOD}, tools/list, tools/call`,
  );
  console.log(` rp:        id=${RP_ID}  origin=${EXPECTED_ORIGIN}  user=${USER_HANDLE}`);
  console.log(` debug:     GET http://localhost:${handle.port}/trades`);
  console.log(`            GET http://localhost:${handle.port}/credentials`);
  console.log(` cors:      ${ALLOWED_ORIGIN}`);
  console.log("──────────────────────────────────────────────");
}
