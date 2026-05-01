import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import {
  APPROVAL_CHALLENGE_CREATE_METHOD,
  APPROVAL_ERROR_CODE,
  type ApprovalChallenge,
  type ApprovalErrorReason,
} from "@mcp-sec/shared";
import { startServer } from "../src/index.js";

let handle: { port: number; close: () => Promise<void> };
let baseUrl: string;

beforeAll(async () => {
  handle = await startServer(0);
  baseUrl = `http://localhost:${handle.port}/mcp`;
});

afterAll(async () => {
  await handle.close();
});

async function newClient(): Promise<Client> {
  const c = new Client({ name: "approval-test", version: "0.0.0" });
  await c.connect(new StreamableHTTPClientTransport(new URL(baseUrl)));
  return c;
}

async function createChallenge(
  c: Client,
  args: Record<string, unknown>,
  toolName = "place_trade",
): Promise<ApprovalChallenge> {
  return (await c.request(
    { method: APPROVAL_CHALLENGE_CREATE_METHOD, params: { toolName, arguments: args } },
    z.any(),
  )) as ApprovalChallenge;
}

async function callTool(
  c: Client,
  args: Record<string, unknown>,
  challengeId: string,
): Promise<unknown> {
  return await c.request(
    {
      method: "tools/call",
      params: {
        name: "place_trade",
        arguments: args,
        approvalEvidence: { method: "stub", challengeId, userConfirmed: true },
      },
    },
    z.any(),
  );
}

function expectApprovalError(err: unknown, reason: ApprovalErrorReason): void {
  expect(err).toBeInstanceOf(McpError);
  const e = err as McpError;
  expect(e.code).toBe(APPROVAL_ERROR_CODE);
  expect((e.data as { reason?: string } | undefined)?.reason).toBe(reason);
}

describe("verified-approval protocol", () => {
  it("happy path: challenge then call with valid evidence executes the trade", async () => {
    const c = await newClient();
    try {
      const args = { symbol: "AAPL", side: "buy", quantity: 100, limit: 180 };
      const challenge = await createChallenge(c, args);
      expect(challenge.challengeId).toMatch(/[0-9a-f-]{36}/);
      expect(challenge.actionHash).toMatch(/^[0-9a-f]{64}$/);
      expect(challenge.displayText).toBe("Buy 100 AAPL at $180");

      const res = (await callTool(c, args, challenge.challengeId)) as {
        structuredContent: { success: true; tradeId: string };
      };
      expect(res.structuredContent.success).toBe(true);
      expect(res.structuredContent.tradeId).toMatch(/[0-9a-f-]{36}/);
    } finally {
      await c.close();
    }
  });

  it("argument tampering: same challengeId with mutated args is rejected", async () => {
    const c = await newClient();
    try {
      const original = { symbol: "AAPL", side: "buy", quantity: 100, limit: 180 };
      const tampered = { symbol: "AAPL", side: "buy", quantity: 1000, limit: 180 };
      const challenge = await createChallenge(c, original);

      const err = await callTool(c, tampered, challenge.challengeId).catch((e) => e);
      expectApprovalError(err, "argument_hash_mismatch");
    } finally {
      await c.close();
    }
  });

  it("replay: a consumed challenge cannot be reused", async () => {
    const c = await newClient();
    try {
      const args = { symbol: "MSFT", side: "sell", quantity: 5, limit: 420 };
      const challenge = await createChallenge(c, args);

      const first = (await callTool(c, args, challenge.challengeId)) as {
        structuredContent: { success: true };
      };
      expect(first.structuredContent.success).toBe(true);

      const err = await callTool(c, args, challenge.challengeId).catch((e) => e);
      expectApprovalError(err, "invalid_challenge");
    } finally {
      await c.close();
    }
  });
});
