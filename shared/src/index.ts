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
