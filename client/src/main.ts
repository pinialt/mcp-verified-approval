import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/browser";
import { z } from "zod";
import {
  APPROVAL_CHALLENGE_CREATE_METHOD,
  APPROVAL_ENROLL_BEGIN_METHOD,
  APPROVAL_ENROLL_FINISH_METHOD,
  APPROVAL_ERROR_CODE,
  VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM,
  VERIFIED_APPROVAL_META_KEY,
  VERIFIED_APPROVAL_REQUIRED,
  policyAcceptsTransports,
  type ApprovalChallenge,
  type PlaceTradeArgs,
  type PlaceTradeResult,
  type TradeRecord,
  type VerifiedApprovalAuthenticatorClass,
  type VerifiedApprovalToolMeta,
} from "@mcp-sec/shared";

const SERVER_BASE = "http://localhost:3030";
const SERVER_URL = `${SERVER_BASE}/mcp`;
const CREDENTIALS_URL = `${SERVER_BASE}/credentials`;
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
const dialogEl = $<HTMLDialogElement>("#approval-dialog");
const dialogTextEl = $<HTMLParagraphElement>("#approval-display-text");
const dialogMetaEl = $<HTMLParagraphElement>("#approval-meta");
const approveBtn = $<HTMLButtonElement>("#approval-approve");
const cancelBtn = $<HTMLButtonElement>("#approval-cancel");
const enrollStatusEl = $<HTMLSpanElement>("#enroll-status");
const enrollBtn = $<HTMLButtonElement>("#enroll-btn");
const enrolledCredsEl = $<HTMLOListElement>("#enrolled-creds");
const enrollLogEl = $<HTMLPreElement>("#enroll-log");

const sessionTrades: TradeRecord[] = [];

// Per-tool approval policy snapshot taken from tools/list. Used both to
// decide whether to drive the approval ceremony for a given tool, and to
// surface a "requires X" hint in the modal.
const toolApprovalPolicy = new Map<string, VerifiedApprovalToolMeta>();

// Last fetched credentials list. Re-fetched after each enrollment and used
// to disable the trade form when no eligible credential is present.
let enrolledCredentials: EnrolledCredential[] = [];

type EnrolledCredential = {
  credentialId: string;
  transports?: string[];
  userHandle: string;
  createdAt: string;
};

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

function elog(line: string, kind: "info" | "ok" | "err" = "info"): void {
  const ts = new Date().toISOString().slice(11, 23);
  const span = document.createElement("span");
  if (kind !== "info") span.className = kind;
  span.textContent = `[${ts}] ${line}\n`;
  enrollLogEl.appendChild(span);
  enrollLogEl.scrollTop = enrollLogEl.scrollHeight;
}

function setEnrollStatus(state: "pending" | "ok" | "err", text: string): void {
  enrollStatusEl.className = `status status--${state}`;
  enrollStatusEl.textContent = text;
}

async function fetchCredentials(): Promise<EnrolledCredential[]> {
  const r = await fetch(CREDENTIALS_URL);
  if (!r.ok) throw new Error(`GET /credentials: HTTP ${r.status}`);
  return (await r.json()) as EnrolledCredential[];
}

function shortenId(id: string): string {
  return id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-6)}` : id;
}

function renderEnrolledCredentials(creds: EnrolledCredential[]): void {
  if (creds.length === 0) {
    setEnrollStatus("err", "not enrolled");
    enrolledCredsEl.innerHTML = `<li class="muted">no credentials enrolled</li>`;
    return;
  }
  const sorted = [...creds].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  setEnrollStatus(
    "ok",
    creds.length === 1 ? "enrolled (1 credential)" : `enrolled (${creds.length} credentials)`,
  );
  enrolledCredsEl.innerHTML = "";
  for (const [i, c] of sorted.entries()) {
    const li = document.createElement("li");
    if (i === 0) li.className = "current";
    const transports = c.transports?.join(",") ?? "—";
    li.textContent = `${c.createdAt}  ${shortenId(c.credentialId)}  [${transports}]`;
    if (i === 0) {
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = "current";
      li.appendChild(badge);
    }
    enrolledCredsEl.appendChild(li);
  }
}

async function refreshEnrolled(): Promise<void> {
  try {
    enrolledCredentials = await fetchCredentials();
    renderEnrolledCredentials(enrolledCredentials);
    updateSubmitButtonEligibility();
  } catch (err) {
    elog(`failed to fetch credentials: ${err instanceof Error ? err.message : String(err)}`, "err");
  }
}

function updateSubmitButtonEligibility(): void {
  const policy = toolApprovalPolicy.get(TOOL_NAME);
  if (!policy || policy.required !== VERIFIED_APPROVAL_REQUIRED) {
    submitEl.disabled = false;
    submitEl.removeAttribute("title");
    return;
  }
  const cls: VerifiedApprovalAuthenticatorClass =
    policy.authenticatorClass ?? VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM;
  const eligible = enrolledCredentials.some((c) => policyAcceptsTransports(cls, c.transports));
  if (eligible) {
    submitEl.disabled = false;
    submitEl.removeAttribute("title");
  } else {
    submitEl.disabled = true;
    submitEl.title = `no eligible authenticator enrolled — go enroll a ${cls} passkey`;
  }
}

function classDescription(cls: VerifiedApprovalAuthenticatorClass): string {
  return cls === VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM
    ? "cross-platform authenticator (e.g. iPhone, hardware key)"
    : "platform authenticator";
}

async function enroll(client: Client): Promise<void> {
  enrollBtn.disabled = true;
  try {
    elog("requesting registration options…");
    const beginRes = (await client.request(
      { method: APPROVAL_ENROLL_BEGIN_METHOD },
      z.object({ options: z.unknown() }),
    )) as { options: PublicKeyCredentialCreationOptionsJSON };
    const optionsJSON = beginRes.options;
    elog(
      `options received (rpId=${optionsJSON.rp.id}, challenge ${optionsJSON.challenge.slice(0, 8)}…)`,
    );
    elog("invoking authenticator — Mac may show QR for hybrid transport, scan with iPhone");
    let response: RegistrationResponseJSON;
    try {
      response = await startRegistration({ optionsJSON });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (err instanceof Error && err.name === "NotAllowedError") {
        elog("authenticator ceremony cancelled or timed out", "err");
      } else {
        elog(`authenticator failed: ${msg}`, "err");
      }
      return;
    }
    elog(`authenticator response received (id ${shortenId(response.id)})`);

    elog("submitting to approval/enroll/finish…");
    try {
      const finishRes = (await client.request(
        { method: APPROVAL_ENROLL_FINISH_METHOD, params: { response } },
        z.object({
          success: z.literal(true),
          credentialId: z.string(),
          createdAt: z.string(),
        }),
      )) as { success: true; credentialId: string; createdAt: string };
      elog(
        `enrolled  credentialId=${shortenId(finishRes.credentialId)}  createdAt=${finishRes.createdAt}`,
        "ok",
      );
    } catch (err) {
      if (err instanceof McpError && err.code === APPROVAL_ERROR_CODE) {
        const reason = (err.data as { reason?: string } | undefined)?.reason ?? "unknown";
        elog(`enrollment rejected (${reason}): ${err.message}`, "err");
      } else {
        elog(`enrollment failed: ${err instanceof Error ? err.message : String(err)}`, "err");
      }
      return;
    }
    await refreshEnrolled();
  } finally {
    enrollBtn.disabled = false;
  }
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

function readToolMeta(meta: unknown): VerifiedApprovalToolMeta | undefined {
  if (!meta || typeof meta !== "object") return undefined;
  const ns = (meta as Record<string, unknown>)[VERIFIED_APPROVAL_META_KEY];
  if (!ns || typeof ns !== "object") return undefined;
  const required = (ns as Record<string, unknown>).required;
  if (required !== VERIFIED_APPROVAL_REQUIRED) return undefined;
  const authenticatorClass = (ns as Record<string, unknown>).authenticatorClass;
  return {
    required: VERIFIED_APPROVAL_REQUIRED,
    ...(authenticatorClass === "platform" || authenticatorClass === "cross-platform"
      ? { authenticatorClass }
      : {}),
  };
}

async function connect(): Promise<Client> {
  const transport = new StreamableHTTPClientTransport(new URL(SERVER_URL));
  const client = new Client({ name: "mcp-sec-client", version: "0.3.0" });
  await client.connect(transport);
  return client;
}

function showApprovalDialog(challenge: ApprovalChallenge, classHint: string | undefined): Promise<boolean> {
  dialogTextEl.textContent = challenge.displayText;
  const hint = classHint ? `requires ${classHint}` : "";
  dialogMetaEl.textContent = [
    hint,
    `challenge ${challenge.challengeId.slice(0, 8)}…`,
    `expires ${challenge.expiresAt}`,
  ]
    .filter(Boolean)
    .join("  ·  ");
  return new Promise((resolve) => {
    let settled = false;
    const settle = (v: boolean): void => {
      if (settled) return;
      settled = true;
      approveBtn.removeEventListener("click", onApprove);
      cancelBtn.removeEventListener("click", onCancel);
      dialogEl.removeEventListener("close", onClose);
      dialogEl.close();
      resolve(v);
    };
    const onApprove = (): void => settle(true);
    const onCancel = (): void => settle(false);
    const onClose = (): void => settle(false);
    approveBtn.addEventListener("click", onApprove);
    cancelBtn.addEventListener("click", onCancel);
    dialogEl.addEventListener("close", onClose);
    dialogEl.showModal();
  });
}

const ChallengeResponseSchema = z.object({
  challengeId: z.string(),
  displayText: z.string(),
  expiresAt: z.string(),
  requestOptions: z.object({
    challenge: z.string(),
    rpId: z.string().optional(),
    allowCredentials: z
      .array(
        z.object({
          type: z.literal("public-key"),
          id: z.string(),
          transports: z.array(z.string()).optional(),
        }),
      )
      .optional(),
    userVerification: z.enum(["required", "preferred", "discouraged"]).optional(),
    timeout: z.number().optional(),
    extensions: z.record(z.string(), z.unknown()).optional(),
  }),
});

async function requestChallenge(client: Client, args: PlaceTradeArgs): Promise<ApprovalChallenge> {
  return (await client.request(
    {
      method: APPROVAL_CHALLENGE_CREATE_METHOD,
      params: { toolName: TOOL_NAME, arguments: args },
    },
    ChallengeResponseSchema,
  )) as ApprovalChallenge;
}

const TradeResultSchema = z
  .object({
    content: z.array(z.unknown()),
    structuredContent: z.object({
      success: z.literal(true),
      tradeId: z.string(),
      executedAt: z.string(),
    }),
  })
  .passthrough();

async function callTradeWithEvidence(
  client: Client,
  args: PlaceTradeArgs,
  challengeId: string,
  response: AuthenticationResponseJSON,
): Promise<PlaceTradeResult> {
  const res = await client.request(
    {
      method: "tools/call",
      params: {
        name: TOOL_NAME,
        arguments: args,
        _meta: {
          [VERIFIED_APPROVAL_META_KEY]: {
            method: "webauthn",
            challengeId,
            response,
          },
        },
      },
    },
    TradeResultSchema,
  );
  return res.structuredContent;
}

function isApprovalError(err: unknown): err is McpError {
  return err instanceof McpError && err.code === APPROVAL_ERROR_CODE;
}

async function handleSubmit(client: Client, args: PlaceTradeArgs): Promise<void> {
  const policy = toolApprovalPolicy.get(TOOL_NAME);
  if (!policy || policy.required !== VERIFIED_APPROVAL_REQUIRED) {
    log(`call ${TOOL_NAME} ${JSON.stringify(args)} (no approval required)`);
    // Phase 3: this branch isn't exercised today (place_trade is annotated)
    // — kept for future tools that don't require approval.
    return;
  }
  const cls: VerifiedApprovalAuthenticatorClass =
    policy.authenticatorClass ?? VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM;

  log("requesting approval challenge…");
  let challenge: ApprovalChallenge;
  try {
    challenge = await requestChallenge(client, args);
  } catch (err) {
    if (isApprovalError(err)) {
      const reason = (err.data as { reason?: string } | undefined)?.reason ?? "unknown";
      log(`challenge rejected (${reason}): ${err.message}`, "err");
    } else {
      log(`challenge request failed: ${err instanceof Error ? err.message : String(err)}`, "err");
    }
    return;
  }
  log(`challenge received: ${challenge.displayText}`);

  const approved = await showApprovalDialog(challenge, classDescription(cls));
  if (!approved) {
    log("user declined", "err");
    return;
  }
  log("user approved");

  log(`invoking authenticator (${cls}) — Mac may show passkey sheet, possibly QR for hybrid…`);
  let response: AuthenticationResponseJSON;
  try {
    response = await startAuthentication({
      optionsJSON: challenge.requestOptions as PublicKeyCredentialRequestOptionsJSON,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (err instanceof Error && err.name === "NotAllowedError") {
      log("authenticator ceremony cancelled or timed out", "err");
    } else {
      log(`authenticator failed: ${msg}`, "err");
    }
    return;
  }
  log(`authenticator response received (id ${shortenId(response.id)})`);

  log("submitting tools/call with webauthn evidence…");
  try {
    const result = await callTradeWithEvidence(client, args, challenge.challengeId, response);
    log(`trade ok  tradeId=${result.tradeId}  executedAt=${result.executedAt}`, "ok");
    sessionTrades.push({ ...args, tradeId: result.tradeId, executedAt: result.executedAt });
    renderTrades();
  } catch (err) {
    if (isApprovalError(err)) {
      const reason = (err.data as { reason?: string } | undefined)?.reason ?? "unknown";
      log(`trade rejected (${reason}): ${err.message}`, "err");
    } else {
      log(`callTool failed: ${err instanceof Error ? err.message : String(err)}`, "err");
    }
  }
}

async function main(): Promise<void> {
  setStatus("pending", "connecting…");
  setEnrollStatus("pending", "checking…");
  let client: Client;
  try {
    client = await connect();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    setStatus("err", "disconnected");
    setEnrollStatus("err", "unavailable");
    log(`connection failed: ${msg}`, "err");
    log(`is the server running on ${SERVER_URL}?`, "err");
    toolsEl.innerHTML = `<li class="muted">unavailable</li>`;
    return;
  }
  setStatus("ok", "connected");
  log("connected");

  await refreshEnrolled();
  enrollBtn.disabled = false;
  enrollBtn.addEventListener("click", () => {
    void enroll(client);
  });

  let tools: Awaited<ReturnType<Client["listTools"]>>["tools"] = [];
  try {
    tools = (await client.listTools()).tools;
    toolsEl.innerHTML = "";
    for (const t of tools) {
      const li = document.createElement("li");
      const meta = readToolMeta(t._meta);
      let badge = "";
      if (meta) {
        toolApprovalPolicy.set(t.name, meta);
        const cls = meta.authenticatorClass ?? VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM;
        badge = `  [verified approval, ${cls}]`;
      }
      li.textContent = `${t.name}${badge} — ${t.description ?? ""}`;
      toolsEl.appendChild(li);
    }
    log(`listed ${tools.length} tool(s)`);
  } catch (err) {
    log(`listTools failed: ${err instanceof Error ? err.message : String(err)}`, "err");
    return;
  }

  if (!tools.some((t) => t.name === TOOL_NAME)) {
    log(`server does not expose ${TOOL_NAME}; form disabled`, "err");
    return;
  }

  updateSubmitButtonEligibility();

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
      await handleSubmit(client, args);
    } finally {
      // Re-evaluate eligibility — credentials may have been added/removed
      // out-of-band, or the call may have failed in a way that still leaves
      // the form usable.
      updateSubmitButtonEligibility();
    }
  });
}

void main();
