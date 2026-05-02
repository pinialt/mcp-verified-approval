// Server-side approval gate.
//
// `createApprovalGate(config)` returns the object the SEP describes as
// "the server's enforcement point": three method handlers
// (`approval/challenge/create`, `approval/enroll/begin`,
// `approval/enroll/finish`) plus the pre-execution check
// `verifyApprovalForCall` that callers invoke from inside their
// `tools/call` handler.
//
// The library does not own the MCP server. The caller wires the gate's
// methods to whichever request-handler API their MCP server exposes; the
// gate is a plain object, not a server.

import { randomBytes, randomUUID } from "node:crypto";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import {
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationResponseJSON,
  WebAuthnCredential,
} from "@simplewebauthn/server";
import {
  APPROVAL_ERROR_CODE,
  VERIFIED_APPROVAL_CAPABILITY_KEY,
  VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM,
  VERIFIED_APPROVAL_REQUIRED,
  canonicalArgs,
  computeActionHash,
  policyAcceptsTransports,
  type ApprovalChallenge,
  type ApprovalErrorReason,
  type AuthenticatorClass,
  type PublicKeyCredentialRequestOptionsJSONShape,
  type VerifiedApprovalToolMeta,
} from "../shared/index.js";

// === Public types ==========================================================

export interface CredentialRecord {
  credentialId: string;
  /**
   * SimpleWebAuthn returns `Uint8Array<ArrayBufferLike>`. Pinning to the SDK
   * type so the registration-time assignment and the verify-call argument
   * line up by construction; otherwise TS narrows to the stricter
   * `Uint8Array<ArrayBuffer>` and refuses the assignment.
   */
  publicKey: WebAuthnCredential["publicKey"];
  counter: number;
  transports?: AuthenticatorTransportFuture[];
  userHandle: string;
  createdAt: string;
}

/**
 * Pluggable storage for enrolled credentials. The Phase 4b ships the
 * in-memory implementation; persistent backends (database, KMS, etc.) are
 * future work and can be added without API changes.
 *
 * Implementations MUST:
 *   - return null from `get` for unknown ids (never throw)
 *   - keep `list` filtered to the supplied `userHandle`
 *   - make `updateCounter` atomic with respect to concurrent reads
 */
export interface CredentialStore {
  get(credentialId: string): Promise<CredentialRecord | null>;
  list(userHandle: string): Promise<CredentialRecord[]>;
  put(record: CredentialRecord): Promise<void>;
  updateCounter(credentialId: string, newCounter: number): Promise<void>;
}

export function createInMemoryCredentialStore(): CredentialStore {
  const map = new Map<string, CredentialRecord>();
  return {
    async get(id) {
      return map.get(id) ?? null;
    },
    async list(userHandle) {
      return [...map.values()].filter((r) => r.userHandle === userHandle);
    },
    async put(record) {
      map.set(record.credentialId, record);
    },
    async updateCounter(id, newCounter) {
      const r = map.get(id);
      if (r) r.counter = newCounter;
    },
  };
}

export interface ApprovalGateConfig {
  /** Relying-Party identifier (typically the public hostname). */
  rpId: string;
  /** Human-readable RP name surfaced in registration ceremonies. */
  rpName: string;
  /** Origin the browser claims in clientDataJSON. Pinned, not derived from headers. */
  expectedOrigin: string;
  /** Per-server identifier baked into the action hash. Prevents cross-server replay. */
  serverId: string;

  /** Approval challenge TTL (default 60 000 ms). */
  challengeTtlMs?: number;
  /** Reaper sweep interval for expired challenges and enrollments (default 30 000 ms). */
  reaperIntervalMs?: number;
  /** Enrollment challenge TTL (default 300 000 ms — five minutes). */
  enrollChallengeTtlMs?: number;
  /** Enrollment-options `timeout` field forwarded to the authenticator (default 300 000 ms). */
  enrollTimeoutMs?: number;
  /** Assertion-options `timeout` field forwarded to the authenticator (default 60 000 ms). */
  assertTimeoutMs?: number;

  /**
   * Resolve the user handle for the current ceremony. Async by design so
   * future multi-user implementations can derive the handle from request
   * context without breaking this surface. For Phase 4b's single-user demo,
   * implementations return the same constant every time.
   */
  getUserHandle: () => Promise<string>;
  /** RP-side display name presented during registration. */
  getUserName: () => Promise<string>;
  /** RP-side displayName presented during registration. */
  getUserDisplayName: () => Promise<string>;

  credentialStore: CredentialStore;
}

export interface ApprovalToolSpec {
  name: string;
  toolMeta: VerifiedApprovalToolMeta;
  /**
   * Produce the human-readable action description shown verbatim to the
   * user inside the approval modal.
   *
   * SECURITY: this string is the user's primary signal about WHAT they are
   * authorizing. It is the most security-sensitive function in the library.
   * Argument-binding makes the signature certify *this exact action hash*,
   * but only this `describe` output makes the user's understanding match
   * the bytes signed. Buggy or attacker-influenced output here defeats
   * argument-binding from the user's perspective.
   *
   * Implementations SHOULD:
   *   - render arguments verbatim — no truncation that could hide a leading
   *     digit or a sign change
   *   - never include LLM-paraphrased text or model-generated summaries —
   *     the description must come from the application, not the agent
   *   - use a deterministic format the user can mentally match against the
   *     form they filled out
   *
   * Required, not optional: tools that gate themselves on verified approval
   * MUST provide a description. The library enforces this at registration
   * time so the contract is checked once, not at every sign-time call.
   */
  describe: (args: unknown) => string;
}

export interface ApprovalGate {
  /** Register a tool the gate is responsible for verifying. */
  registerTool(spec: ApprovalToolSpec): void;

  /** Handler for the `approval/challenge/create` MCP method. */
  handleChallengeCreate(params: {
    toolName: string;
    arguments: Record<string, unknown>;
  }): Promise<ApprovalChallenge>;

  /** Handler for the `approval/enroll/begin` MCP method. */
  handleEnrollBegin(): Promise<{ options: PublicKeyCredentialCreationOptionsJSON }>;

  /** Handler for the `approval/enroll/finish` MCP method. */
  handleEnrollFinish(params: {
    response: unknown;
  }): Promise<{ success: true; credentialId: string; createdAt: string }>;

  /**
   * Pre-execution gate. Call this from inside your `tools/call` handler
   * AFTER you've looked up the tool. Atomically:
   *   1. validates the evidence shape and looks up the pending challenge,
   *   2. looks up the credential and re-checks authenticator-class policy,
   *   3. verifies the WebAuthn signature via @simplewebauthn/server,
   *   4. independently recomputes the action hash from `args` and compares,
   *   5. consumes the challenge (single-use),
   *   6. updates the credential's counter.
   *
   * Throws `McpError(APPROVAL_ERROR_CODE, message, { reason })` on rejection,
   * where `reason` is an `ApprovalErrorReason`. Returns void on success — the
   * caller may then execute the tool.
   */
  verifyApprovalForCall(toolName: string, args: unknown, evidence: unknown): Promise<void>;

  /**
   * Returns the gate's authoritative
   * `_meta["io.modelcontextprotocol/verified-approval"]` block for
   * `toolName`, or `null` if the tool is not registered with the gate.
   * Use this from your `tools/list` handler to surface gating metadata, and
   * from your `tools/call` handler to decide whether to invoke
   * `verifyApprovalForCall`.
   */
  getToolApprovalMeta(toolName: string): VerifiedApprovalToolMeta | null;

  /** Stop the internal reaper intervals. Idempotent. */
  shutdown(): void;
}

/**
 * Returns the partial capabilities object a caller merges into their MCP
 * server's `initialize` capability declaration:
 *
 *     new McpServer(
 *       { name, version },
 *       { capabilities: { tools: {}, ...getApprovalCapabilityDeclaration() } },
 *     );
 *
 * Shape: `{ extensions: { verifiedApproval: {} } }`. The capability lives
 * under the SDK's `extensions` slot — the spec-defined namespace for
 * non-spec capabilities — rather than as a bare top-level key, because the
 * MCP SDK's `ServerCapabilitiesSchema` strips unknown top-level keys and
 * `extensions` is the designed extension point. The `verifiedApproval` key
 * remains BARE within `extensions` (not reverse-DNS); the asymmetry with
 * the `_meta` extension key holds — bare within a closed namespace,
 * namespaced when colliding in an open namespace. See docs/DECISIONS.md
 * "Capability declaration placement" for the full rationale.
 *
 * The empty object value leaves room for future capability sub-options
 * without breaking the initial shape. Pure function — no gate instance or
 * config required, since capability declaration happens at server
 * construction time, often before the gate exists.
 */
export function getApprovalCapabilityDeclaration() {
  return {
    extensions: { [VERIFIED_APPROVAL_CAPABILITY_KEY]: {} },
  } as const;
}

/**
 * Construct an `McpError` carrying the verified-approval error code and a
 * structured `data.reason` discriminator. Re-exported so demo callers can
 * raise their own approval-domain errors with the same shape (e.g. for the
 * `missing_evidence` case before the gate is reached).
 */
export function approvalError(
  reason: ApprovalErrorReason | "no_pending_enrollment" | "verification_failed",
  message: string,
): McpError {
  return new McpError(APPROVAL_ERROR_CODE, message, { reason });
}

// === Implementation ========================================================

const DEFAULT_CHALLENGE_TTL_MS = 60_000;
const DEFAULT_REAPER_INTERVAL_MS = 30_000;
const DEFAULT_ENROLL_CHALLENGE_TTL_MS = 5 * 60_000;
const DEFAULT_ENROLL_TIMEOUT_MS = 5 * 60_000;
const DEFAULT_ASSERT_TIMEOUT_MS = 60_000;

type PendingChallenge = {
  toolName: string;
  canonicalArgsJson: string;
  actionHashHex: string;
  nonceBase64Url: string;
  wireChallenge: string;
  expiresAt: number;
  consumed: boolean;
};

type RegisteredApprovalTool = {
  name: string;
  toolMeta: VerifiedApprovalToolMeta;
  describe: (args: unknown) => string;
};

export function createApprovalGate(config: ApprovalGateConfig): ApprovalGate {
  const {
    rpId,
    rpName,
    expectedOrigin,
    serverId,
    challengeTtlMs = DEFAULT_CHALLENGE_TTL_MS,
    reaperIntervalMs = DEFAULT_REAPER_INTERVAL_MS,
    enrollChallengeTtlMs = DEFAULT_ENROLL_CHALLENGE_TTL_MS,
    enrollTimeoutMs = DEFAULT_ENROLL_TIMEOUT_MS,
    assertTimeoutMs = DEFAULT_ASSERT_TIMEOUT_MS,
    getUserHandle,
    getUserName,
    getUserDisplayName,
    credentialStore,
  } = config;

  const tools = new Map<string, RegisteredApprovalTool>();
  const challenges = new Map<string, PendingChallenge>();
  const pendingEnrollments = new Map<string, { challenge: string; expiresAt: number }>();

  const challengeReaper = setInterval(() => {
    const now = Date.now();
    for (const [id, c] of challenges) {
      if (c.consumed || c.expiresAt <= now) challenges.delete(id);
    }
  }, reaperIntervalMs);
  challengeReaper.unref?.();

  const enrollmentReaper = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of pendingEnrollments) {
      if (v.expiresAt <= now) pendingEnrollments.delete(k);
    }
  }, reaperIntervalMs);
  enrollmentReaper.unref?.();

  async function handleChallengeCreate(params: {
    toolName: string;
    arguments: Record<string, unknown>;
  }): Promise<ApprovalChallenge> {
    const tool = tools.get(params.toolName);
    if (!tool) {
      throw new McpError(-32602, `Unknown tool: ${params.toolName}`);
    }
    if (tool.toolMeta.required !== VERIFIED_APPROVAL_REQUIRED) {
      throw new McpError(-32602, `Tool ${params.toolName} does not require verified approval`);
    }

    const policy: AuthenticatorClass =
      tool.toolMeta.authenticatorClass ?? VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM;

    const userHandle = await getUserHandle();
    const allCreds = await credentialStore.list(userHandle);
    const eligible = allCreds.filter((c) => policyAcceptsTransports(policy, c.transports));
    if (eligible.length === 0) {
      throw approvalError(
        "no_eligible_credential",
        `No enrolled credential satisfies the ${policy} authenticator-class policy for ${params.toolName}`,
      );
    }

    const argsCanonical = canonicalArgs(params.arguments);
    const actionHashBytes = await computeActionHash(params.toolName, argsCanonical, serverId);
    const actionHashHex = Buffer.from(actionHashBytes).toString("hex");
    const nonceBytes = randomBytes(32);
    // Wire challenge: base64url(nonce || actionHash). The 32-byte nonce gives
    // freshness; the 32-byte actionHash binds this signature to the specific
    // canonicalized argument string. The server stores both halves and
    // compares them at verify time: the SDK's expectedChallenge check pins
    // the wire bytes, AND we recompute the action hash from the actual call
    // args (defense in depth — mismatch -> argument_hash_mismatch). See
    // docs/DECISIONS.md for the binding rationale and byte-order spec.
    const wireChallengeBytes = Buffer.concat([nonceBytes, Buffer.from(actionHashBytes)]);
    const wireChallenge = wireChallengeBytes.toString("base64url");

    const challengeId = randomUUID();
    const expiresAtMs = Date.now() + challengeTtlMs;
    challenges.set(challengeId, {
      toolName: params.toolName,
      canonicalArgsJson: argsCanonical,
      actionHashHex,
      nonceBase64Url: nonceBytes.toString("base64url"),
      wireChallenge,
      expiresAt: expiresAtMs,
      consumed: false,
    });

    const requestOptions: PublicKeyCredentialRequestOptionsJSONShape = {
      challenge: wireChallenge,
      rpId,
      allowCredentials: eligible.map((c) => ({
        type: "public-key" as const,
        id: c.credentialId,
        transports: c.transports,
      })),
      userVerification: "required",
      timeout: assertTimeoutMs,
      // Phase 4 mitigation 1: WebAuthn L3 hint to nudge the OS picker toward
      // the cross-device transport for synced credentials. As of macOS 26.4.1
      // / Safari 26.4 / Chrome 147 (May 2026), Apple's system picker does
      // not honor this hint — see verification/phase-4-mitigation-1.md. The
      // field is forwarded for forward compatibility with platforms that may
      // later respect it.
      hints: ["hybrid"],
    };

    const displayText = tool.describe(params.arguments);
    console.log(
      `[approval] challenge ${challengeId} for ${params.toolName} (${displayText}); ${eligible.length} eligible cred(s) under policy=${policy}`,
    );
    return {
      challengeId,
      displayText,
      expiresAt: new Date(expiresAtMs).toISOString(),
      requestOptions,
    };
  }

  async function verifyApprovalForCall(
    toolName: string,
    args: unknown,
    evidence: unknown,
  ): Promise<void> {
    const tool = tools.get(toolName);
    if (!tool) {
      throw new McpError(-32602, `Unknown tool: ${toolName}`);
    }
    if (tool.toolMeta.required !== VERIFIED_APPROVAL_REQUIRED) {
      throw new McpError(-32602, `Tool ${toolName} does not require verified approval`);
    }

    if (!evidence || typeof evidence !== "object") {
      throw approvalError("missing_evidence", "Approval evidence required");
    }
    const evidenceObj = evidence as {
      method?: unknown;
      challengeId?: unknown;
      response?: unknown;
    };
    if (
      evidenceObj.method !== "webauthn" ||
      typeof evidenceObj.challengeId !== "string" ||
      !evidenceObj.response ||
      typeof evidenceObj.response !== "object"
    ) {
      throw approvalError("missing_evidence", "Approval evidence missing or malformed");
    }
    const challengeId = evidenceObj.challengeId;
    const response = evidenceObj.response as Record<string, unknown>;

    // 1. Look up the pending challenge with split-reason precision.
    const stored = challenges.get(challengeId);
    if (!stored) throw approvalError("challenge_unknown", "Approval challenge not found");
    if (stored.consumed) throw approvalError("challenge_consumed", "Approval challenge already consumed");
    if (stored.expiresAt <= Date.now()) throw approvalError("challenge_expired", "Approval challenge expired");
    if (stored.toolName !== tool.name) {
      throw approvalError("challenge_wrong_tool", "Approval challenge issued for a different tool");
    }

    // 2. Look up the credential.
    const responseId = String((response as { id?: unknown }).id ?? "");
    const cred = await credentialStore.get(responseId);
    if (!cred) throw approvalError("unknown_credential", "Credential not enrolled");

    // 3. Authenticator-class policy. Filtered out at challenge issuance, but
    //    re-checked here as defense in depth: a malicious client could re-use
    //    a challenge created for one user with an ineligible credential they
    //    enrolled later, or forge an allowCredentials list, etc.
    const policy = tool.toolMeta.authenticatorClass;
    if (!policyAcceptsTransports(policy, cred.transports)) {
      throw approvalError(
        "authenticator_class_mismatch",
        `Credential transports ${JSON.stringify(cred.transports ?? [])} do not satisfy ${policy ?? "cross-platform"} policy`,
      );
    }

    // 4. Verify the signature. SimpleWebAuthn enforces strictly-monotonic
    //    counter when stored counter > 0; map that specific failure to
    //    signature_counter_regression and everything else to
    //    signature_verification_failed.
    const oldCounter = cred.counter;
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: response as unknown as AuthenticationResponseJSON,
        expectedChallenge: stored.wireChallenge,
        expectedOrigin,
        expectedRPID: rpId,
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
    const callCanonical = canonicalArgs(args ?? {});
    const callHashBytes = await computeActionHash(tool.name, callCanonical, serverId);
    const callHashHex = Buffer.from(callHashBytes).toString("hex");
    if (callHashHex !== stored.actionHashHex) {
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
    //    In a multi-process server (future work) this needs a real CAS (DB
    //    row lock, Redis SETNX) so two workers can't both consume.
    if (stored.consumed) {
      throw approvalError("challenge_consumed", "Approval challenge already consumed (race)");
    }
    stored.consumed = true;

    // 7. Persist the new counter so a replay across sessions trips the counter
    //    check. Apple's synced passkeys often report counter 0 forever —
    //    that's spec-permitted and means the counter check isn't load-bearing
    //    for those credentials. (challenge_consumed is the freshness
    //    guarantee; counter is defense-in-depth against authenticator
    //    cloning.)
    await credentialStore.updateCounter(cred.credentialId, verification.authenticationInfo.newCounter);
    console.log(
      `[approval] consumed ${challengeId} for ${tool.name}; counter ${oldCounter} -> ${verification.authenticationInfo.newCounter}`,
    );
  }

  async function handleEnrollBegin(): Promise<{ options: PublicKeyCredentialCreationOptionsJSON }> {
    const userHandle = await getUserHandle();
    const userName = await getUserName();
    const userDisplayName = await getUserDisplayName();
    const existing = await credentialStore.list(userHandle);
    const exclude = existing.map((c) => ({ id: c.credentialId, transports: c.transports }));
    const userIDBytes = new TextEncoder().encode(userHandle);
    const options = await generateRegistrationOptions({
      rpName,
      rpID: rpId,
      userName,
      userID: userIDBytes,
      userDisplayName,
      attestationType: "none",
      excludeCredentials: exclude,
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
      timeout: enrollTimeoutMs,
    });
    pendingEnrollments.set(userHandle, {
      challenge: options.challenge,
      expiresAt: Date.now() + enrollChallengeTtlMs,
    });
    console.log(
      `[enroll] options issued for ${userHandle} (challenge ${options.challenge.slice(0, 8)}…, ${exclude.length} existing creds excluded)`,
    );
    return { options };
  }

  async function handleEnrollFinish(params: {
    response: unknown;
  }): Promise<{ success: true; credentialId: string; createdAt: string }> {
    const userHandle = await getUserHandle();
    const pending = pendingEnrollments.get(userHandle);
    if (!pending || pending.expiresAt <= Date.now()) {
      throw approvalError("no_pending_enrollment", "No pending enrollment or challenge expired");
    }
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: params.response as unknown as RegistrationResponseJSON,
        expectedChallenge: pending.challenge,
        expectedOrigin,
        expectedRPID: rpId,
        requireUserVerification: false,
      });
    } catch (err) {
      pendingEnrollments.delete(userHandle);
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`[enroll] verification threw: ${msg}`);
      throw approvalError("verification_failed", `Registration verification failed: ${msg}`);
    }
    pendingEnrollments.delete(userHandle);
    if (!verification.verified || !verification.registrationInfo) {
      throw approvalError("verification_failed", "Registration not verified");
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
    await credentialStore.put(record);
    console.log(
      `[enroll] credential stored: ${credential.id.slice(0, 12)}… (${credential.transports?.join(",") ?? "no transports"}) at ${record.createdAt}`,
    );
    return {
      success: true,
      credentialId: credential.id,
      createdAt: record.createdAt,
    };
  }

  return {
    registerTool(spec) {
      tools.set(spec.name, {
        name: spec.name,
        toolMeta: spec.toolMeta,
        describe: spec.describe,
      });
    },
    handleChallengeCreate,
    handleEnrollBegin,
    handleEnrollFinish,
    verifyApprovalForCall,
    getToolApprovalMeta(toolName) {
      const t = tools.get(toolName);
      return t ? t.toolMeta : null;
    },
    shutdown() {
      clearInterval(challengeReaper);
      clearInterval(enrollmentReaper);
    },
  };
}

// Re-export the SEP-quotable surface so callers don't need a second import.
export {
  ApprovalEvidenceSchema,
  ApprovalChallengeSchema,
  VERIFIED_APPROVAL_TOOL_META_KEY,
  VERIFIED_APPROVAL_REQUEST_META_KEY,
  VERIFIED_APPROVAL_CAPABILITY_KEY,
  VERIFIED_APPROVAL_REQUIRED,
  VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM,
  VERIFIED_APPROVAL_CLASS_PLATFORM,
  APPROVAL_CHALLENGE_CREATE_METHOD,
  APPROVAL_ENROLL_BEGIN_METHOD,
  APPROVAL_ENROLL_FINISH_METHOD,
  APPROVAL_ERROR_CODE,
  type ApprovalChallenge,
  type ApprovalEvidence,
  type ApprovalErrorReason,
  type AuthenticatorClass,
  type VerifiedApprovalToolMeta,
} from "../shared/index.js";
