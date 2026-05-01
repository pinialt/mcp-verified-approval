import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { z } from "zod";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import WebAuthnEmulator, {
  AuthenticatorEmulator,
  PasskeysCredentialsMemoryRepository,
} from "nid-webauthn-emulator";
import {
  APPROVAL_ENROLL_BEGIN_METHOD,
  APPROVAL_ENROLL_FINISH_METHOD,
  APPROVAL_ERROR_CODE,
  EXPECTED_ORIGIN,
} from "@mcp-sec/shared";
import { startServer } from "../src/index.js";

let handle: { port: number; close: () => Promise<void> };
let baseUrl: string;
let credentialsUrl: string;

beforeAll(async () => {
  handle = await startServer(0);
  baseUrl = `http://localhost:${handle.port}/mcp`;
  credentialsUrl = `http://localhost:${handle.port}/credentials`;
});

afterAll(async () => {
  await handle.close();
});

async function newClient(): Promise<Client> {
  const c = new Client({ name: "enrollment-test", version: "0.0.0" });
  await c.connect(new StreamableHTTPClientTransport(new URL(baseUrl)));
  return c;
}

async function listCredentials(): Promise<unknown[]> {
  const r = await fetch(credentialsUrl);
  return (await r.json()) as unknown[];
}

async function beginEnrollment(c: Client): Promise<{ options: Record<string, unknown> }> {
  return (await c.request({ method: APPROVAL_ENROLL_BEGIN_METHOD }, z.any())) as {
    options: Record<string, unknown>;
  };
}

async function finishEnrollment(c: Client, response: unknown): Promise<unknown> {
  return await c.request(
    { method: APPROVAL_ENROLL_FINISH_METHOD, params: { response } },
    z.any(),
  );
}

// Fresh emulator with an isolated in-memory credential repo. Without this,
// the emulator's default repository is file-based and persists across both
// tests *and* test runs, which makes excludeCredentials trip CTAP2_ERR_CREDENTIAL_EXCLUDED.
function freshEmulator(): WebAuthnEmulator {
  return new WebAuthnEmulator(
    new AuthenticatorEmulator({
      credentialsRepository: new PasskeysCredentialsMemoryRepository(),
    }),
  );
}

function encodeClientDataJSON(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
}

function decodeClientDataJSON(b64url: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(b64url, "base64url").toString("utf8"));
}

describe("WebAuthn enrollment", () => {
  it("happy path: begin then finish with a valid emulated registration response stores the credential", async () => {
    const c = await newClient();
    try {
      const before = (await listCredentials()) as unknown[];

      const { options } = await beginEnrollment(c);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const response = freshEmulator().createJSON(EXPECTED_ORIGIN, options as any);

      const result = (await finishEnrollment(c, response)) as {
        success: true;
        credentialId: string;
        createdAt: string;
      };
      expect(result.success).toBe(true);
      expect(result.credentialId).toMatch(/^[A-Za-z0-9_-]+$/); // base64url
      expect(result.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);

      const after = (await listCredentials()) as Array<{
        credentialId: string;
        userHandle: string;
        createdAt: string;
      }>;
      expect(after.length).toBe(before.length + 1);
      expect(after.some((r) => r.credentialId === result.credentialId)).toBe(true);
    } finally {
      await c.close();
    }
  });

  it("argument tampering: mutated clientDataJSON challenge is rejected with verification_failed", async () => {
    const c = await newClient();
    try {
      const beforeCount = (await listCredentials()).length;

      const { options } = await beginEnrollment(c);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const response = freshEmulator().createJSON(EXPECTED_ORIGIN, options as any);

      // Flip the challenge inside clientDataJSON. With attestation "none"
      // there's no inner signature to also break — the failure path is
      // verifyRegistrationResponse comparing decoded.challenge to
      // expectedChallenge.
      const decoded = decodeClientDataJSON(response.response.clientDataJSON);
      decoded.challenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      const tampered = {
        ...response,
        response: { ...response.response, clientDataJSON: encodeClientDataJSON(decoded) },
      };

      const err = await finishEnrollment(c, tampered).catch((e) => e);
      expect(err).toBeInstanceOf(McpError);
      const e = err as McpError;
      expect(e.code).toBe(APPROVAL_ERROR_CODE);
      expect((e.data as { reason?: string } | undefined)?.reason).toBe("verification_failed");

      const afterCount = (await listCredentials()).length;
      expect(afterCount).toBe(beforeCount);
    } finally {
      await c.close();
    }
  });

  it("wrong origin: clientDataJSON claiming evil.example.com is rejected with verification_failed", async () => {
    // The emulator does its own browser-style origin/RP-ID validation and
    // refuses to sign for mismatched origins, which is the *browser's* job.
    // The threat model we want to test is "malicious client bypasses that
    // check and ships an attestation claiming a different origin" — the
    // server's expectedOrigin check is the ground-truth defense. We
    // simulate that by getting a valid response from the emulator at the
    // legitimate origin, then tampering clientDataJSON.origin before
    // submission.
    const c = await newClient();
    try {
      const beforeCount = (await listCredentials()).length;

      const { options } = await beginEnrollment(c);
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const response = freshEmulator().createJSON(EXPECTED_ORIGIN, options as any);

      const decoded = decodeClientDataJSON(response.response.clientDataJSON);
      decoded.origin = "http://evil.example.com";
      const tampered = {
        ...response,
        response: { ...response.response, clientDataJSON: encodeClientDataJSON(decoded) },
      };

      const err = await finishEnrollment(c, tampered).catch((e) => e);
      expect(err).toBeInstanceOf(McpError);
      const e = err as McpError;
      expect(e.code).toBe(APPROVAL_ERROR_CODE);
      expect((e.data as { reason?: string } | undefined)?.reason).toBe("verification_failed");

      const afterCount = (await listCredentials()).length;
      expect(afterCount).toBe(beforeCount);
    } finally {
      await c.close();
    }
  });
});
