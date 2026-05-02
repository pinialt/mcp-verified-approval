// Demo-deployment configuration and tool types.
//
// After Phase 4b the verified-approval protocol vocabulary moved to
// `mcp-verified-approval/shared`. This workspace keeps only the values that
// are specific to *this demo's deployment* (the RP, the origin, the single
// user) and to *this demo's tool* (`place_trade`).
//
// The library accepts the deployment values via configuration; the server
// imports them from here and passes them to `createApprovalGate`.

// === Demo deployment constants =============================================

// RP_ID and EXPECTED_ORIGIN are pinned constants — never derived from request
// headers (a known WebAuthn footgun). The demo client and demo server both
// need these in lock-step; tests pin EXPECTED_ORIGIN as the emulator's
// origin parameter.
export const RP_ID = "localhost" as const;
export const RP_NAME = "MCP Verified Approval" as const;
export const EXPECTED_ORIGIN = "http://localhost:5173" as const;

// Single-user demo. Multi-user is post-v1; all credentials enrolled in this
// build are bound to this one user.
export const USER_HANDLE = "phase-2-dev-user" as const;
export const USER_NAME = "MCP Demo User" as const;
export const USER_DISPLAY_NAME = "Demo" as const;

// === place_trade tool types ================================================

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
