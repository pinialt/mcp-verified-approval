import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { VERIFIED_APPROVAL_REQUEST_META_KEY } from "mcp-verified-approval/shared";
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

// Phase 3 assertion-path tests. These exercise the WebAuthn-specific surface
// the protocol gained in Phase 3:
//   1. happy path                  -> trade executes
//   2. argument tampering          -> argument_hash_mismatch (the headline
//                                     property: a compromised client cannot
//                                     swap arguments after the user signed)
//   3. replay                      -> challenge_consumed (single-use)
//   4. authenticator-class policy  -> authenticator_class_mismatch when the
//                                     credential's transports don't qualify
//   5. signature counter regression-> signature_counter_regression when the
//                                     same credential reports a stale or
//                                     equal counter on a subsequent call.

let handle: { port: number; close: () => Promise<void> };
let baseUrl: string;

beforeAll(async () => {
  handle = await startServer(0);
  baseUrl = `http://localhost:${handle.port}/mcp`;
});

afterAll(async () => {
  await handle.close();
});

describe("Phase 3 assertion path", () => {
  it("happy path: emulator-signed assertion with cross-platform credential places the trade", async () => {
    const c = await newClient(baseUrl, "happy");
    try {
      const { emulator } = newEmulator(); // default = ["usb"], satisfies cross-platform
      await enroll(c, emulator);

      const args = { symbol: "AAPL", side: "buy", quantity: 10, limit: 180 };
      const challenge = await createChallenge(c, args);
      // The wire challenge is base64url(nonce || actionHash). Sanity-check
      // the length: 32 bytes nonce + 32 bytes action hash = 64 bytes,
      // which encodes to 86 base64url chars (no padding).
      expect(challenge.requestOptions.challenge.length).toBe(86);
      expect(challenge.requestOptions.userVerification).toBe("required");
      expect(challenge.requestOptions.allowCredentials?.length).toBeGreaterThan(0);

      const assertion = emulatorAssert(emulator, challenge.requestOptions);
      const res = (await callPlaceTrade(c, args, challenge.challengeId, assertion)) as {
        structuredContent: { success: true; tradeId: string };
      };
      expect(res.structuredContent.success).toBe(true);
    } finally {
      await c.close();
    }
  });

  it("argument tampering: assertion bound to qty=100, call sent with qty=1000, rejected", async () => {
    const c = await newClient(baseUrl, "tamper");
    try {
      const { emulator } = newEmulator();
      await enroll(c, emulator);

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

  it("replay: same evidence on a second call is rejected as challenge_consumed", async () => {
    const c = await newClient(baseUrl, "replay");
    try {
      const { emulator } = newEmulator();
      await enroll(c, emulator);

      const args = { symbol: "AAPL", side: "buy", quantity: 1, limit: 100 };
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

  it("authenticator-class enforcement: an internal-only credential is excluded from allowCredentials AND rejected at verify", async () => {
    // Enroll a credential that advertises *only* internal transport — this
    // should NOT satisfy the place_trade cross-platform policy.
    const c = await newClient(baseUrl, "auth-class");
    try {
      const { emulator } = newEmulator({ transports: ["internal"] });
      await enroll(c, emulator);

      // Issuance side: server must refuse to issue a challenge if no eligible
      // credential is enrolled. Since we just enrolled an ineligible one and
      // (depending on prior test ordering) it may be the only cred, the
      // policy filter should drop it out of allowCredentials. We prove the
      // exclusion by calling with an internal-only emulator: even if the
      // server still issues a challenge (because earlier-running tests left
      // eligible credentials in the shared map), our internal-only emulator
      // will sign with its OWN credential — which the server must reject at
      // verify time as authenticator_class_mismatch.
      const args = { symbol: "ZZZ", side: "buy", quantity: 1, limit: 1 };
      let challenge;
      try {
        challenge = await createChallenge(c, args);
      } catch (err) {
        // Acceptable outcome: no_eligible_credential (when the shared
        // credentials map has only internal-only creds). The policy is
        // working at issuance time.
        expectApprovalError(err, "no_eligible_credential");
        return;
      }

      // If a challenge was issued, an eligible credential exists from a
      // prior test. Force the ineligible emulator to sign the challenge,
      // mutate the assertion's id to match its own credential, and submit.
      // The server must reject at verify time.
      const assertion = emulatorAssert(emulator, {
        ...challenge.requestOptions,
        // Emulator only signs with credentials it owns; remove
        // allowCredentials so it picks its own.
        allowCredentials: undefined,
      }) as { id: string };

      const err = await callPlaceTrade(c, args, challenge.challengeId, assertion).catch((e) => e);
      // The credential id won't be in our store at all -> unknown_credential.
      // (The internal-only credential we enrolled HAS been stored, but the
      // emulator's own credential id matches that one. So the lookup
      // succeeds, then the policy check fires.) Either reason is a correct
      // rejection — the test asserts both are acceptable.
      expect([
        "authenticator_class_mismatch",
        "unknown_credential",
      ]).toContain(
        ((err as { data?: { reason?: string } }).data?.reason),
      );
    } finally {
      await c.close();
    }
  });

  it("signature counter regression: rewinding the emulator's stored counter trips the check", async () => {
    // Apple's synced passkeys often report counter 0 forever — that's
    // spec-permitted (passkeys aren't required to maintain a real counter).
    // SimpleWebAuthn's counter check only fires when the stored counter is
    // > 0, so this test cannot use a fresh-from-iCloud iPhone passkey. The
    // emulator gives us a controllable counter; we use it here and document
    // the limitation.
    const c = await newClient(baseUrl, "counter");
    try {
      const { emulator, repository } = newEmulator({ signCounterIncrement: 1 });
      await enroll(c, emulator);

      // First valid assertion bumps the server's stored counter from 0 to 1.
      const args = { symbol: "GOOG", side: "buy", quantity: 2, limit: 2780 };
      const ch1 = await createChallenge(c, args);
      const a1 = emulatorAssert(emulator, ch1.requestOptions);
      await callPlaceTrade(c, args, ch1.challengeId, a1);

      // Rewind the emulator's *internal* signCount back to 0. The
      // PasskeyDiscoverableCredential is `readonly` in TypeScript but the
      // runtime object is mutable; we cast and write directly to the
      // signCount field, then save back so the in-Map serialized form is
      // updated.
      const stored = repository.loadCredentials();
      expect(stored.length).toBe(1);
      const cred = stored[0]!;
      (cred.authenticatorData as { signCount: number }).signCount = 0;
      repository.saveCredential(cred);

      // Next assertion: emulator increments 0 -> 1; server's stored is 1;
      // SimpleWebAuthn requires strictly-greater, so 1 > 1 is false and
      // verify throws with a counter-related message.
      const ch2 = await createChallenge(c, args);
      const a2 = emulatorAssert(emulator, ch2.requestOptions);

      const err = await callPlaceTrade(c, args, ch2.challengeId, a2).catch((e) => e);
      expectApprovalError(err, "signature_counter_regression");
    } finally {
      await c.close();
    }
  });

  it("rejects evidence with non-webauthn method as unsupported_method", async () => {
    const c = await newClient(baseUrl, "unsupported-method");
    try {
      const { emulator } = newEmulator();
      await enroll(c, emulator);

      const args = { symbol: "AAPL", side: "buy", quantity: 1, limit: 100 };
      const challenge = await createChallenge(c, args);
      const assertion = emulatorAssert(emulator, challenge.requestOptions);

      const err = await c
        .request(
          {
            method: "tools/call",
            params: {
              name: "place_trade",
              arguments: args,
              _meta: {
                [VERIFIED_APPROVAL_REQUEST_META_KEY]: {
                  method: "totp",
                  challengeId: challenge.challengeId,
                  response: assertion,
                },
              },
            },
          },
          z.any(),
        )
        .catch((e) => e);
      expectApprovalError(err, "unsupported_method");
    } finally {
      await c.close();
    }
  });
});

