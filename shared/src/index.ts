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

// === Phase 1: verified-approval protocol ===

export const VERIFIED_APPROVAL_META_KEY = "verifiedApproval/required" as const;
export const VERIFIED_APPROVAL_VERIFIED = "verified" as const;

// Key inside tools/call params._meta where the approval evidence lives.
// Symmetric with the tool-listing _meta annotation above; both sides of the
// extension reside in _meta so the eventual SEP can describe the whole
// mechanism as _meta-resident.
export const VERIFIED_APPROVAL_META_FIELD = "verifiedApproval" as const;

export type ApprovalChallenge = {
  challengeId: string;
  nonce: string;
  actionHash: string;
  displayText: string;
  expiresAt: string;
};

export type ApprovalEvidence = {
  method: "stub";
  challengeId: string;
  userConfirmed: true;
};

export type ApprovalErrorReason =
  | "missing_evidence"
  | "invalid_challenge"
  | "argument_hash_mismatch";

export const APPROVAL_ERROR_CODE = -32001;

export const APPROVAL_CHALLENGE_CREATE_METHOD = "approval/challenge/create";

export type ApprovalChallengeCreateParams = {
  toolName: string;
  arguments: Record<string, unknown>;
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
export const RP_NAME = "MCP Verified Approval (Phase 2)" as const;
export const EXPECTED_ORIGIN = "http://localhost:5173" as const;

// Single-user demo. Multi-user is post-v1; all credentials enrolled in
// Phase 2 are bound to this one user.
export const USER_HANDLE = "phase-2-dev-user" as const;
export const USER_NAME = "Phase 2 Demo User" as const;
export const USER_DISPLAY_NAME = "Demo" as const;

export const APPROVAL_ENROLL_BEGIN_METHOD = "approval/enroll/begin" as const;
export const APPROVAL_ENROLL_FINISH_METHOD = "approval/enroll/finish" as const;
