import canonicalize from "canonicalize";

export type TradeSide = "buy" | "sell";

export type PlaceTradeArgs = {
  symbol: string;
  side: TradeSide;
  quantity: number;
  limit: number;
};

export type PlaceTradeResult = {
  success: true;
  tradeId: string;
  executedAt: string;
};

export type TradeRecord = PlaceTradeArgs & {
  tradeId: string;
  executedAt: string;
};

// === Verified-approval extension: shared types & constants ===

// Phase 3 unifies the tool-side and request-side _meta namespaces. Both
// sides now address the verified-approval extension under a single key
// "verifiedApproval"; the value differs by side:
//   tool._meta.verifiedApproval     -> { required, authenticatorClass? }
//   params._meta.verifiedApproval   -> ApprovalEvidence (the assertion)
//
// Phase 1 used a flat slash-key form (tool._meta["verifiedApproval/required"])
// on the tool side and a nested object on the request side; the asymmetry was
// the first thing a careful reviewer would notice. Phase 3 picks the nested
// shape on both sides. See docs/DECISIONS.md.
export const VERIFIED_APPROVAL_META_KEY = "verifiedApproval" as const;

export const VERIFIED_APPROVAL_REQUIRED = "verified" as const;
export const VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM = "cross-platform" as const;
export const VERIFIED_APPROVAL_CLASS_PLATFORM = "platform" as const;

export type VerifiedApprovalAuthenticatorClass =
  | typeof VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM
  | typeof VERIFIED_APPROVAL_CLASS_PLATFORM;

// Shape of tool._meta.verifiedApproval. Default authenticatorClass when
// omitted is "cross-platform" — tools must opt in to "platform" deliberately
// (see docs/DECISIONS.md, "Authenticator class policy").
export type VerifiedApprovalToolMeta = {
  required: typeof VERIFIED_APPROVAL_REQUIRED;
  authenticatorClass?: VerifiedApprovalAuthenticatorClass;
};

// Decide whether a credential's transports satisfy a tool's policy. Both
// the server (filtering allowCredentials at challenge issuance and rejecting
// at verify time) and the client (UI affordances, eligibility hints) call
// this — keeping the decision in one place avoids drift.
//
// "cross-platform" is the default and the high-sensitivity choice: the
// credential MUST be presentable from a separate device, so its transports
// MUST include at least one of hybrid / usb / nfc / ble. A credential
// advertising only "internal" is bound to this Mac and cannot satisfy a
// cross-platform policy. (See verification/phase-2.md, Finding 3 — this
// is a use-time, not enrollment-provenance, property.)
//
// "platform" tools accept anything enrolled.
const ROAMING_TRANSPORTS = new Set(["hybrid", "usb", "nfc", "ble"]);
export function policyAcceptsTransports(
  policy: VerifiedApprovalAuthenticatorClass | undefined,
  transports: readonly string[] | undefined,
): boolean {
  const effective = policy ?? VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM;
  if (effective === VERIFIED_APPROVAL_CLASS_PLATFORM) return true;
  if (!transports || transports.length === 0) return false;
  return transports.some((t) => ROAMING_TRANSPORTS.has(t));
}

// Local mirror of @simplewebauthn's AuthenticationResponseJSON, kept here so
// shared/ doesn't pull in @simplewebauthn at runtime. Server and client each
// import the real type from their respective @simplewebauthn package; the
// shapes line up structurally.
export type AuthenticationResponseJSON = {
  id: string;
  rawId: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
  type: "public-key";
  clientExtensionResults: Record<string, unknown>;
  authenticatorAttachment?: string;
};

// The webauthn-only evidence variant. Phase 3 removed the "stub" variant
// entirely — there's no production path that accepts unsigned approval.
// Schema is a single-variant z.object today; switch to z.discriminatedUnion
// when a second method (e.g. delegated-session, hardware token) materializes.
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

export const APPROVAL_ERROR_CODE = -32001;

export const APPROVAL_CHALLENGE_CREATE_METHOD = "approval/challenge/create";

export type ApprovalChallengeCreateParams = {
  toolName: string;
  arguments: Record<string, unknown>;
};

// Phase 3 wire shape (decision B). The flat nonce/actionHash siblings from
// Phase 1 are dropped — the client never used them. The request-options
// blob is what the client passes into startAuthentication; it contains the
// challenge bytes (base64url(nonce || actionHash)), the filtered
// allowCredentials, and the timeout.
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
  extensions?: Record<string, unknown>;
};

export type ApprovalChallenge = {
  challengeId: string;
  displayText: string;
  expiresAt: string;
  requestOptions: PublicKeyCredentialRequestOptionsJSONShape;
};

// RFC 8785 JCS over the tool arguments. Both sides must hash the same string.
export function canonicalArgs(args: unknown): string {
  const out = canonicalize(args);
  if (out === undefined) {
    throw new Error("canonicalArgs: input canonicalizes to undefined");
  }
  return out;
}

// === Phase 2: WebAuthn enrollment ===

// RP_ID and EXPECTED_ORIGIN are hardcoded constants — never derived from
// request headers (a known WebAuthn footgun). Both sides import the same
// values; the server passes them to verifyRegistrationResponse and the
// client uses RP_ID via the options blob the server returns.
export const RP_ID = "localhost" as const;
export const RP_NAME = "MCP Verified Approval" as const;
export const EXPECTED_ORIGIN = "http://localhost:5173" as const;

// Single-user demo. Multi-user is post-v1; all credentials enrolled in
// this build are bound to this one user.
export const USER_HANDLE = "phase-2-dev-user" as const;
export const USER_NAME = "MCP Demo User" as const;
export const USER_DISPLAY_NAME = "Demo" as const;

export const APPROVAL_ENROLL_BEGIN_METHOD = "approval/enroll/begin" as const;
export const APPROVAL_ENROLL_FINISH_METHOD = "approval/enroll/finish" as const;
