import { z } from "zod";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import WebAuthnEmulator, {
  AuthenticatorEmulator,
  PasskeysCredentialsMemoryRepository,
} from "nid-webauthn-emulator";
import { expect } from "vitest";
import { EXPECTED_ORIGIN } from "@mcp-sec/shared";
import {
  APPROVAL_CHALLENGE_CREATE_METHOD,
  APPROVAL_ENROLL_BEGIN_METHOD,
  APPROVAL_ENROLL_FINISH_METHOD,
  APPROVAL_ERROR_CODE,
  VERIFIED_APPROVAL_REQUEST_META_KEY,
  type ApprovalChallenge,
  type ApprovalErrorReason,
} from "mcp-verified-approval/shared";

export const TOOL = "place_trade";

export async function newClient(baseUrl: string, name = "phase-3-test"): Promise<Client> {
  const c = new Client({ name, version: "0.0.0" });
  await c.connect(new StreamableHTTPClientTransport(new URL(baseUrl)));
  return c;
}

// AuthenticatorTransport in the emulator's types is a structural string
// matching the WebAuthn spec; accepting string[] keeps this test helper
// uncoupled from whichever exact alias the emulator settles on.
export type EmulatorOpts = {
  transports?: string[];
  signCounterIncrement?: number;
};

export function newEmulator(opts: EmulatorOpts = {}): {
  emulator: WebAuthnEmulator;
  repository: PasskeysCredentialsMemoryRepository;
} {
  const repository = new PasskeysCredentialsMemoryRepository();
  const params: Record<string, unknown> = { credentialsRepository: repository };
  if (opts.transports !== undefined) params.transports = opts.transports;
  if (opts.signCounterIncrement !== undefined) params.signCounterIncrement = opts.signCounterIncrement;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const emulator = new WebAuthnEmulator(new AuthenticatorEmulator(params as any));
  return { emulator, repository };
}

export async function enroll(
  c: Client,
  emulator: WebAuthnEmulator,
): Promise<{ credentialId: string }> {
  const begin = (await c.request({ method: APPROVAL_ENROLL_BEGIN_METHOD }, z.any())) as {
    options: Record<string, unknown>;
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const response = emulator.createJSON(EXPECTED_ORIGIN, begin.options as any);
  const finish = (await c.request(
    { method: APPROVAL_ENROLL_FINISH_METHOD, params: { response } },
    z.any(),
  )) as { credentialId: string };
  return { credentialId: finish.credentialId };
}

export async function createChallenge(
  c: Client,
  args: Record<string, unknown>,
  toolName: string = TOOL,
): Promise<ApprovalChallenge> {
  return (await c.request(
    { method: APPROVAL_CHALLENGE_CREATE_METHOD, params: { toolName, arguments: args } },
    z.any(),
  )) as ApprovalChallenge;
}

export function emulatorAssert(
  emulator: WebAuthnEmulator,
  requestOptions: ApprovalChallenge["requestOptions"],
): unknown {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return emulator.getJSON(EXPECTED_ORIGIN, requestOptions as any);
}

export async function callPlaceTrade(
  c: Client,
  args: Record<string, unknown>,
  challengeId: string,
  assertionResponse: unknown,
): Promise<unknown> {
  return await c.request(
    {
      method: "tools/call",
      params: {
        name: TOOL,
        arguments: args,
        _meta: {
          [VERIFIED_APPROVAL_REQUEST_META_KEY]: {
            method: "webauthn",
            challengeId,
            response: assertionResponse,
          },
        },
      },
    },
    z.any(),
  );
}

export function expectApprovalError(err: unknown, reason: ApprovalErrorReason): void {
  expect(err).toBeInstanceOf(McpError);
  const e = err as McpError;
  expect(e.code).toBe(APPROVAL_ERROR_CODE);
  expect((e.data as { reason?: string } | undefined)?.reason).toBe(reason);
}
