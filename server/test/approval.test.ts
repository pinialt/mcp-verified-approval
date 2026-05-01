import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { startServer } from "../src/index.js";
import {
  callPlaceTrade,
  createChallenge,
  emulatorAssert,
  enroll,
  expectApprovalError,
  newClient,
  newEmulator,
} from "./helpers.js";

// Phase 1 tests, carried into Phase 3 with the stub-evidence path removed.
// What used to assert against `invalid_challenge` now asserts against the
// specific split reasons (challenge_consumed, challenge_unknown, etc.) per
// the verification-report carry-forward. The wire path is real WebAuthn
// assertions produced by the emulator — no production code accepts stub
// evidence anymore.
//
// The assertion.test.ts file repeats the happy/tampering/replay scenarios at
// a different level of focus: this file frames them as protocol-shape tests
// (challenge binding, single-use, freshness), assertion.test.ts frames them
// as part of the WebAuthn-specific surface (signature verify, auth-class,
// counter regression). The duplication is intentional.

let handle: { port: number; close: () => Promise<void> };
let baseUrl: string;

beforeAll(async () => {
  handle = await startServer(0);
  baseUrl = `http://localhost:${handle.port}/mcp`;
});

afterAll(async () => {
  await handle.close();
});

async function setUpClientAndEmulatedCredential(): Promise<{
  c: Client;
  emulator: ReturnType<typeof newEmulator>["emulator"];
}> {
  const c = await newClient(baseUrl);
  // Default emulator advertises USB transport — satisfies the
  // place_trade cross-platform policy.
  const { emulator } = newEmulator();
  await enroll(c, emulator);
  return { c, emulator };
}

describe("verified-approval protocol (carry-over)", () => {
  it("happy path: challenge then call with a valid assertion executes the trade", async () => {
    const { c, emulator } = await setUpClientAndEmulatedCredential();
    try {
      const args = { symbol: "AAPL", side: "buy", quantity: 100, limit: 180 };
      const challenge = await createChallenge(c, args);
      const assertion = emulatorAssert(emulator, challenge.requestOptions);

      const res = (await callPlaceTrade(c, args, challenge.challengeId, assertion)) as {
        structuredContent: { success: true; tradeId: string };
      };
      expect(res.structuredContent.success).toBe(true);
      expect(res.structuredContent.tradeId).toMatch(/[0-9a-f-]{36}/);
    } finally {
      await c.close();
    }
  });

  it("argument tampering: same challengeId with mutated args is rejected as argument_hash_mismatch", async () => {
    const { c, emulator } = await setUpClientAndEmulatedCredential();
    try {
      const original = { symbol: "AAPL", side: "buy", quantity: 100, limit: 180 };
      const tampered = { symbol: "AAPL", side: "buy", quantity: 1000, limit: 180 };
      const challenge = await createChallenge(c, original);
      const assertion = emulatorAssert(emulator, challenge.requestOptions);

      const err = await callPlaceTrade(c, tampered, challenge.challengeId, assertion).catch((e) => e);
      expectApprovalError(err, "argument_hash_mismatch");
    } finally {
      await c.close();
    }
  });

  it("replay: a consumed challenge cannot be reused (challenge_consumed)", async () => {
    const { c, emulator } = await setUpClientAndEmulatedCredential();
    try {
      const args = { symbol: "MSFT", side: "sell", quantity: 5, limit: 420 };
      const challenge = await createChallenge(c, args);
      const assertion = emulatorAssert(emulator, challenge.requestOptions);

      const first = (await callPlaceTrade(c, args, challenge.challengeId, assertion)) as {
        structuredContent: { success: true };
      };
      expect(first.structuredContent.success).toBe(true);

      const err = await callPlaceTrade(c, args, challenge.challengeId, assertion).catch((e) => e);
      expectApprovalError(err, "challenge_consumed");
    } finally {
      await c.close();
    }
  });
});
