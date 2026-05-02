// Shared protocol vocabulary for the verified-approval extension.
//
// This module is the SEP-quotable surface: every constant, type, and pure
// function exported from here corresponds to something the spec text names.
// Both the server gate and the client ceremony import from this single source.
//
// No Node-only or browser-only imports at runtime: webcrypto.subtle is reached
// through globalThis, the WebAuthn JSON types are pulled in via `import type`
// only.

import canonicalize from "canonicalize";
import { z } from "zod";
import type {
  AuthenticationResponseJSON as SdkAuthenticationResponseJSON,
  PublicKeyCredentialHint,
} from "@simplewebauthn/browser";

// === The io.modelcontextprotocol/verified-approval _meta namespace =========
//
// The verified-approval extension occupies a single namespace key
// "io.modelcontextprotocol/verified-approval" at TWO distinct _meta
// locations. The shapes differ by location; the value is **never** the same
// object on the wire — they share only the namespace label.
//
//   1. Tool-listing _meta:
//      `tool._meta["io.modelcontextprotocol/verified-approval"]`
//      Value: VerifiedApprovalToolMeta
//      Set by the server when registering a tool; read by clients during
//      tools/list to decide whether the tool is gated and (if so) what
//      authenticator class is required.
//
//   2. tools/call request _meta:
//      `params._meta["io.modelcontextprotocol/verified-approval"]`
//      Value: ApprovalEvidence
//      Set by the client on tools/call to attach the WebAuthn assertion;
//      read by the server gate to verify approval before executing the tool.
//
// The two named constants below have the same string value but are intended
// to be used at their respective read sites for clarity. Mixing them up is a
// type-level no-op but a readability regression.

/**
 * Tool-listing _meta key. Value at this key is a {@link VerifiedApprovalToolMeta}.
 * Use at the read site `tool._meta?.[VERIFIED_APPROVAL_TOOL_META_KEY]`.
 */
export const VERIFIED_APPROVAL_TOOL_META_KEY =
  "io.modelcontextprotocol/verified-approval" as const;

/**
 * tools/call request _meta key. Value at this key is an {@link ApprovalEvidence}.
 * Use at the read site `params._meta?.[VERIFIED_APPROVAL_REQUEST_META_KEY]`.
 *
 * Same string value as {@link VERIFIED_APPROVAL_TOOL_META_KEY} but a distinct
 * symbol used at the request-side read site. The two are kept separate so
 * call sites are self-documenting about which value shape applies.
 */
export const VERIFIED_APPROVAL_REQUEST_META_KEY =
  "io.modelcontextprotocol/verified-approval" as const;

// === Capability key ========================================================
//
// Advertised in a server's `ServerCapabilities` during the `initialize`
// handshake when the server supports the verified-approval extension. BARE
// on purpose — capability keys for spec-recognized features are bare
// strings, not reverse-DNS namespaced (compare `elicitation` in the
// elicitation spec). The asymmetry with the `_meta` extension keys above
// (`io.modelcontextprotocol/verified-approval`, namespaced) is deliberate:
// `_meta` is an open namespace where collision prevention requires
// reverse-DNS, while capabilities live in the closed handshake namespace
// the spec controls. See docs/DECISIONS.md "Meta-key rename" entry
// (2026-05-02) for the full asymmetry decision.

export const VERIFIED_APPROVAL_CAPABILITY_KEY = "verifiedApproval" as const;

// === Tool-side meta values =================================================

export const VERIFIED_APPROVAL_REQUIRED = "verified" as const;
export const VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM = "cross-platform" as const;
export const VERIFIED_APPROVAL_CLASS_PLATFORM = "platform" as const;

export type AuthenticatorClass =
  | typeof VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM
  | typeof VERIFIED_APPROVAL_CLASS_PLATFORM;

/**
 * Shape of `tool._meta["io.modelcontextprotocol/verified-approval"]`.
 *
 * `authenticatorClass` defaults to `"cross-platform"` when omitted — tools
 * must opt in to `"platform"` deliberately. See docs/DECISIONS.md, section
 * "Authenticator class policy", for what each class delivers (capability
 * filtering, not use-time guarantee).
 */
export type VerifiedApprovalToolMeta = {
  required: typeof VERIFIED_APPROVAL_REQUIRED;
  authenticatorClass?: AuthenticatorClass;
};

// === Method names and error code ===========================================

export const APPROVAL_CHALLENGE_CREATE_METHOD = "approval/challenge/create" as const;
export const APPROVAL_ENROLL_BEGIN_METHOD = "approval/enroll/begin" as const;
export const APPROVAL_ENROLL_FINISH_METHOD = "approval/enroll/finish" as const;

/**
 * JSON-RPC error code used for all approval-domain rejections. The structured
 * `data.reason` field carries an {@link ApprovalErrorReason} discriminator
 * that callers should branch on rather than parsing the message.
 */
export const APPROVAL_ERROR_CODE = -32001 as const;

// === Wire types ============================================================

/**
 * The challenge bytes the WebAuthn authenticator signs over are produced by:
 *
 *     actionHashBytes = SHA-256( utf8(toolName) || 0x00
 *                                || utf8(canonicalArgsJson) || 0x00
 *                                || utf8(serverId) )                   // 32 bytes
 *     nonceBytes      = crypto.randomBytes(32)                         // 32 bytes
 *     wireChallenge   = base64url( nonceBytes || actionHashBytes )    // 86 b64url chars
 *
 * Order is `nonce || actionHash`. See docs/DECISIONS.md "Action-hash
 * byte-order specification" for the full rationale.
 */
export type PublicKeyCredentialRequestOptionsJSONShape = {
  challenge: string;
  rpId?: string;
  allowCredentials?: Array<{
    type: "public-key";
    id: string;
    transports?: string[];
  }>;
  userVerification?: "required" | "preferred" | "discouraged";
  timeout?: number;
  hints?: PublicKeyCredentialHint[];
  extensions?: Record<string, unknown>;
};

/**
 * Returned by `approval/challenge/create`. The client passes
 * `requestOptions` straight into `startAuthentication`; the human-readable
 * `displayText` is what the client SHOULD display verbatim in its approval
 * modal.
 */
export type ApprovalChallenge = {
  challengeId: string;
  displayText: string;
  /** ISO-8601 timestamp; the challenge is unusable after this. */
  expiresAt: string;
  requestOptions: PublicKeyCredentialRequestOptionsJSONShape;
};

/**
 * Re-export of @simplewebauthn/browser's AuthenticationResponseJSON. Type-only
 * import — no runtime dependency from this module.
 */
export type AuthenticationResponseJSON = SdkAuthenticationResponseJSON;

/**
 * Value shape at `params._meta["io.modelcontextprotocol/verified-approval"]`
 * on a tools/call request. Single-variant today; switch to
 * `z.discriminatedUnion("method", ...)` when a second method materializes.
 */
export type ApprovalEvidence = {
  method: "webauthn";
  challengeId: string;
  response: AuthenticationResponseJSON;
};

export type ApprovalErrorReason =
  | "missing_evidence"
  | "challenge_unknown"
  | "challenge_expired"
  | "challenge_consumed"
  | "challenge_wrong_tool"
  | "argument_hash_mismatch"
  | "unknown_credential"
  | "authenticator_class_mismatch"
  | "signature_verification_failed"
  | "signature_counter_regression"
  | "no_eligible_credential";

// === Schemas ===============================================================

/**
 * Zod schema for `ApprovalEvidence`. Single-variant today; the `method`
 * discriminant is in place so future methods are an additive change at every
 * read site.
 */
export const ApprovalEvidenceSchema = z.object({
  method: z.literal("webauthn"),
  challengeId: z.string(),
  response: z.record(z.string(), z.unknown()),
});

/**
 * Zod schema for `ApprovalChallenge`. Used by clients to validate the
 * challenge response.
 */
export const ApprovalChallengeSchema = z.object({
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
    hints: z.array(z.string()).optional(),
    extensions: z.record(z.string(), z.unknown()).optional(),
  }),
});

// === Pure functions ========================================================

/**
 * RFC 8785 (JCS) canonicalization of arbitrary tool arguments. Both client
 * and server MUST produce byte-identical output for byte-identical input —
 * argument-binding depends on it.
 *
 * Implemented via `canonicalize@3.0.0` (Erdtman, RFC 8785 author). Throws if
 * the input canonicalizes to undefined (e.g. a bare function value).
 */
export function canonicalArgs(args: unknown): string {
  const out = canonicalize(args);
  if (out === undefined) {
    throw new Error("canonicalArgs: input canonicalizes to undefined");
  }
  return out;
}

/**
 * SHA-256 binding of (toolName, canonicalArgsJson, serverId). Returns the
 * raw 32-byte digest — callers concatenate with the 32-byte nonce to produce
 * the wire challenge.
 *
 * Both client and server must produce byte-identical output for the same
 * inputs. Uses `globalThis.crypto.subtle`, available in Node 20+ and all
 * supported browsers.
 *
 * The three inputs are joined with a 0x00 separator before hashing to prevent
 * length-extension confusion across fields:
 *
 *     hash = SHA-256( utf8(toolName) || 0x00
 *                     || utf8(canonicalArgsJson) || 0x00
 *                     || utf8(serverId) )
 */
export async function computeActionHash(
  toolName: string,
  canonicalArgsJson: string,
  serverId: string,
): Promise<Uint8Array> {
  const data = new TextEncoder().encode(`${toolName} ${canonicalArgsJson} ${serverId}`);
  const buf = await globalThis.crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(buf);
}

// === Authenticator-class capability filter =================================

const ROAMING_TRANSPORTS = new Set(["hybrid", "usb", "nfc", "ble"]);

/**
 * Capability check: do these transports satisfy a tool's authenticator-class
 * policy? Both the server (filtering allowCredentials at challenge issuance
 * AND rejecting at verify time) and the client (UI eligibility hints) call
 * this — keeping the decision in one place avoids drift.
 *
 * - `"cross-platform"` (default): transports MUST include at least one of
 *   hybrid / usb / nfc / ble. A credential advertising only `["internal"]`
 *   is bound to this device and does not satisfy the policy.
 * - `"platform"`: any enrolled credential is acceptable.
 *
 * Note: this is a CAPABILITY check. It does not guarantee that a synced
 * credential is presented from a separate device at sign time. See
 * docs/DECISIONS.md, "Authenticator class policy", for the full caveat.
 */
export function policyAcceptsTransports(
  policy: AuthenticatorClass | undefined,
  transports: readonly string[] | undefined,
): boolean {
  const effective = policy ?? VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM;
  if (effective === VERIFIED_APPROVAL_CLASS_PLATFORM) return true;
  if (!transports || transports.length === 0) return false;
  return transports.some((t) => ROAMING_TRANSPORTS.has(t));
}

// Re-exported so callers don't need a separate `@simplewebauthn/browser`
// import for this WebAuthn L3 type union.
export type { PublicKeyCredentialHint };
