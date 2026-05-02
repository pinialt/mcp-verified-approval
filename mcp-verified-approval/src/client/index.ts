// Client-side ceremony.
//
// `createApprovalClient(config)` returns the object the SEP describes as
// "the client's part of the ceremony": detect whether a tool is gated,
// run the assertion ceremony to get evidence, and run the enrollment
// ceremony.
//
// The library does NOT take ownership of the MCP transport — the caller
// passes a `request` function with the same shape as
// `@modelcontextprotocol/sdk/client/Client["request"]`.
//
// The library does NOT take ownership of the modal UI — the caller passes
// an `onChallengeReceived` callback that decides "approve" or "decline".
// This separation keeps the protocol surface clean of UX choices.

import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/browser";
import { z, type ZodType } from "zod";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import {
  APPROVAL_CHALLENGE_CREATE_METHOD,
  APPROVAL_ENROLL_BEGIN_METHOD,
  APPROVAL_ENROLL_FINISH_METHOD,
  APPROVAL_ERROR_CODE,
  ApprovalChallengeSchema,
  VERIFIED_APPROVAL_REQUIRED,
  VERIFIED_APPROVAL_TOOL_META_KEY,
  type ApprovalChallenge,
  type ApprovalEvidence,
  type AuthenticatorClass,
  type VerifiedApprovalToolMeta,
} from "../shared/index.js";

export interface ApprovalClientConfig {
  /**
   * Caller's MCP request function. Same shape as
   * `Client["request"]` from `@modelcontextprotocol/sdk/client/index.js`.
   * The library doesn't construct the transport — it just dispatches
   * requests through whatever the caller provides.
   */
  request: <T>(
    req: { method: string; params?: unknown },
    schema: ZodType<T>,
  ) => Promise<T>;
}

/**
 * Outcome of a single approval ceremony. Decline and "no eligible credential"
 * are routine outcomes the caller should handle in normal flow; only genuine
 * errors (network failure, browser refused to invoke authenticator, malformed
 * server response) cause `requestApprovalEvidence` to throw.
 */
export type ApprovalOutcome =
  | { status: "approved"; evidence: ApprovalEvidence }
  | { status: "declined"; reason: "user_declined" }
  | { status: "no_eligible_credential" };

export interface ApprovalClient {
  /**
   * Returns the verified-approval `_meta` block for `tool`, or `null` if the
   * tool is not gated. Use this on each entry of `tools/list` to decide
   * whether `requestApprovalEvidence` is required for calls to this tool.
   */
  detectApprovalRequirement(tool: { _meta?: unknown }): VerifiedApprovalToolMeta | null;

  /**
   * Run the full assertion ceremony for one tool call:
   *   1. POST `approval/challenge/create` with `(toolName, arguments)`,
   *   2. await `onChallengeReceived(challenge)` — caller renders modal here
   *      and returns `"approve"` or `"decline"`,
   *   3. invoke the browser WebAuthn API (`startAuthentication`),
   *   4. return the evidence object the caller attaches to the eventual
   *      `tools/call` request at
   *      `params._meta["io.modelcontextprotocol/verified-approval"]`.
   *
   * Returns:
   *   - `{ status: "approved", evidence }` on success,
   *   - `{ status: "declined", reason: "user_declined" }` if the caller's
   *     modal returned `"decline"`,
   *   - `{ status: "no_eligible_credential" }` if the server rejected
   *     challenge creation with that reason.
   *
   * Throws on network failure, browser refusing the authenticator
   * (NotAllowedError, etc.), malformed server responses, or any other
   * MCP error reason.
   */
  requestApprovalEvidence(args: {
    toolName: string;
    arguments: unknown;
    onChallengeReceived: (
      challenge: ApprovalChallenge,
    ) => Promise<"approve" | "decline">;
  }): Promise<ApprovalOutcome>;

  /**
   * Run the enrollment ceremony:
   *   1. POST `approval/enroll/begin`,
   *   2. invoke the browser WebAuthn API (`startRegistration`),
   *   3. POST `approval/enroll/finish` with the registration response.
   *
   * Throws on cancellation, network failure, or server rejection — the
   * caller can branch on `err.name === "NotAllowedError"` for the
   * user-cancelled-the-OS-prompt case.
   */
  enroll(): Promise<{ success: true; credentialId: string; createdAt: string }>;
}

const EnrollBeginResponseSchema = z.object({ options: z.unknown() });
const EnrollFinishResponseSchema = z.object({
  success: z.literal(true),
  credentialId: z.string(),
  createdAt: z.string(),
});

export function createApprovalClient(config: ApprovalClientConfig): ApprovalClient {
  const { request } = config;

  function detectApprovalRequirement(tool: { _meta?: unknown }): VerifiedApprovalToolMeta | null {
    const meta = tool._meta;
    if (!meta || typeof meta !== "object") return null;
    const ns = (meta as Record<string, unknown>)[VERIFIED_APPROVAL_TOOL_META_KEY];
    if (!ns || typeof ns !== "object") return null;
    const required = (ns as Record<string, unknown>).required;
    if (required !== VERIFIED_APPROVAL_REQUIRED) return null;
    const authenticatorClass = (ns as Record<string, unknown>).authenticatorClass;
    return {
      required: VERIFIED_APPROVAL_REQUIRED,
      ...(authenticatorClass === "platform" || authenticatorClass === "cross-platform"
        ? { authenticatorClass: authenticatorClass as AuthenticatorClass }
        : {}),
    };
  }

  async function requestApprovalEvidence(args: {
    toolName: string;
    arguments: unknown;
    onChallengeReceived: (
      challenge: ApprovalChallenge,
    ) => Promise<"approve" | "decline">;
  }): Promise<ApprovalOutcome> {
    let challenge: ApprovalChallenge;
    try {
      challenge = await request(
        {
          method: APPROVAL_CHALLENGE_CREATE_METHOD,
          params: { toolName: args.toolName, arguments: args.arguments },
        },
        ApprovalChallengeSchema as ZodType<ApprovalChallenge>,
      );
    } catch (err) {
      if (err instanceof McpError && err.code === APPROVAL_ERROR_CODE) {
        const reason = (err.data as { reason?: string } | undefined)?.reason;
        if (reason === "no_eligible_credential") {
          return { status: "no_eligible_credential" };
        }
      }
      throw err;
    }

    const decision = await args.onChallengeReceived(challenge);
    if (decision === "decline") {
      return { status: "declined", reason: "user_declined" };
    }

    const response = await startAuthentication({
      optionsJSON: challenge.requestOptions as PublicKeyCredentialRequestOptionsJSON,
    });

    return {
      status: "approved",
      evidence: {
        method: "webauthn",
        challengeId: challenge.challengeId,
        response,
      },
    };
  }

  async function enroll(): Promise<{ success: true; credentialId: string; createdAt: string }> {
    const beginRes = await request(
      { method: APPROVAL_ENROLL_BEGIN_METHOD },
      EnrollBeginResponseSchema,
    );
    const optionsJSON = beginRes.options as PublicKeyCredentialCreationOptionsJSON;
    const response: RegistrationResponseJSON = await startRegistration({ optionsJSON });
    const finishRes = await request(
      { method: APPROVAL_ENROLL_FINISH_METHOD, params: { response } },
      EnrollFinishResponseSchema,
    );
    return finishRes;
  }

  return {
    detectApprovalRequirement,
    requestApprovalEvidence,
    enroll,
  };
}

// Re-export the SEP-quotable surface so callers don't need a second import.
export {
  VERIFIED_APPROVAL_TOOL_META_KEY,
  VERIFIED_APPROVAL_REQUEST_META_KEY,
  VERIFIED_APPROVAL_REQUIRED,
  VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM,
  VERIFIED_APPROVAL_CLASS_PLATFORM,
  APPROVAL_CHALLENGE_CREATE_METHOD,
  APPROVAL_ENROLL_BEGIN_METHOD,
  APPROVAL_ENROLL_FINISH_METHOD,
  APPROVAL_ERROR_CODE,
  policyAcceptsTransports,
  type ApprovalChallenge,
  type ApprovalEvidence,
  type ApprovalErrorReason,
  type AuthenticatorClass,
  type VerifiedApprovalToolMeta,
} from "../shared/index.js";
