# Phase 4b verification

Reference branch: `phase-4b-library-extraction`
Last commit (step d): `8b580dc` — *phase-4b-step-d: extract client ceremony to mcp-verified-approval/client*
Status: **automated portion complete; manual hardware run pending user action.**

## What Phase 4b is

Reorganization, not feature work. The verified-approval logic that lived
in the demo `server/` and `client/` workspaces has been extracted into a
single library `mcp-verified-approval/` with subpath exports `./shared`,
`./server`, `./client`. The demo workspaces are now consumers of the
library through its public API.

The protocol is unchanged. No new wire bytes, no new method shapes, no
test removed. The 11 existing tests pass through the library.

## Library shape

```
mcp-verified-approval/
  package.json              # exports: ".", "./shared", "./server", "./client"
  tsconfig.json
  src/
    index.ts                # root re-export of the SEP-quotable wire vocabulary
    shared/index.ts         # canonicalArgs, computeActionHash,
                            #   policyAcceptsTransports, the _meta keys, error
                            #   reasons, schemas, types
    server/index.ts         # createApprovalGate, CredentialStore,
                            #   createInMemoryCredentialStore, ApprovalGate
                            #   (handleChallengeCreate / handleEnrollBegin /
                            #    handleEnrollFinish / verifyApprovalForCall)
    client/index.ts         # createApprovalClient, ApprovalClient
                            #   (detectApprovalRequirement /
                            #    requestApprovalEvidence / enroll)
                            #   ApprovalOutcome discriminated union
```

Subpath resolution works via the `exports` map in
[mcp-verified-approval/package.json](../mcp-verified-approval/package.json#L8-L25).
The repo's `tsconfig.base.json` already pins `moduleResolution: "NodeNext"`,
which resolves the subpath conditions and reads the `types` field — demo
imports like `import { createApprovalGate } from "mcp-verified-approval/server"`
type-check against the matching `dist/server/index.d.ts`.

## Public API as the SEP surface

The names and shapes below are what the eventual SEP can quote directly.

### Shared (`mcp-verified-approval/shared`)

Constants:
- `VERIFIED_APPROVAL_TOOL_META_KEY` — value at `tool._meta.verifiedApproval`
  is a `VerifiedApprovalToolMeta`.
- `VERIFIED_APPROVAL_REQUEST_META_KEY` — value at
  `params._meta.verifiedApproval` on `tools/call` is an `ApprovalEvidence`.
- `VERIFIED_APPROVAL_REQUIRED`, `VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM`,
  `VERIFIED_APPROVAL_CLASS_PLATFORM`.
- `APPROVAL_CHALLENGE_CREATE_METHOD`, `APPROVAL_ENROLL_BEGIN_METHOD`,
  `APPROVAL_ENROLL_FINISH_METHOD`, `APPROVAL_ERROR_CODE`.

Two named constants for the namespace key, both equal to `"verifiedApproval"`,
make the read sites self-documenting about which value shape applies. This was
the resolution to one of the brief's API-review revisions.

Pure functions:
- `canonicalArgs(args: unknown): string` — RFC 8785 (JCS).
- `computeActionHash(toolName, canonicalArgsJson, serverId): Promise<Uint8Array>`
  — SHA-256 over `utf8(toolName) || 0x00 || utf8(canonicalArgsJson) || 0x00 || utf8(serverId)`.
  Returns 32 raw bytes; uses `globalThis.crypto.subtle` so the same function
  works in Node 20+ and browsers.
- `policyAcceptsTransports(policy, transports): boolean` — capability filter
  for the authenticator-class policy.

Schemas: `ApprovalEvidenceSchema`, `ApprovalChallengeSchema`.

Types: `ApprovalChallenge`, `ApprovalEvidence`, `ApprovalErrorReason`,
`AuthenticatorClass`, `VerifiedApprovalToolMeta`,
`PublicKeyCredentialRequestOptionsJSONShape`, `AuthenticationResponseJSON`,
`PublicKeyCredentialHint`.

### Server (`mcp-verified-approval/server`)

```ts
function createApprovalGate(config: ApprovalGateConfig): ApprovalGate;

interface ApprovalGate {
  registerTool(spec: ApprovalToolSpec): void;
  handleChallengeCreate(params): Promise<ApprovalChallenge>;
  handleEnrollBegin(): Promise<{ options: PublicKeyCredentialCreationOptionsJSON }>;
  handleEnrollFinish(params): Promise<{ success: true; credentialId: string; createdAt: string }>;
  verifyApprovalForCall(toolName, args, evidence): Promise<void>;
  getToolApprovalMeta(toolName): VerifiedApprovalToolMeta | null;
  shutdown(): void;
}
```

`ApprovalGateConfig` takes the values that were hardcoded in Phase 0–3:
`rpId`, `rpName`, `expectedOrigin`, `serverId`, all TTL/timeout knobs, and
the user-handle/name/displayName resolvers. The user resolvers are
`() => Promise<string>` rather than string fields so a future multi-user
implementation is an additive change rather than a breaking one.

`ApprovalToolSpec.describe` is **required** (per the brief's API review —
revision #4). The JSDoc on the field marks it as the most security-sensitive
function in the library: it produces the displayText shown verbatim to the
user, and argument-binding is only as strong as the user's understanding
matching the bytes signed. Implementations are explicitly told not to use
LLM-paraphrased text or model-generated summaries.

`CredentialStore` is a four-method interface (`get`, `list`, `put`,
`updateCounter`) and `createInMemoryCredentialStore()` ships the v0
implementation. Persistent backends (DB, KMS) are future work and a
non-breaking addition.

### Client (`mcp-verified-approval/client`)

```ts
function createApprovalClient(config: ApprovalClientConfig): ApprovalClient;

interface ApprovalClient {
  detectApprovalRequirement(tool): VerifiedApprovalToolMeta | null;
  requestApprovalEvidence(args): Promise<ApprovalOutcome>;
  enroll(): Promise<{ success: true; credentialId: string; createdAt: string }>;
}

type ApprovalOutcome =
  | { status: "approved"; evidence: ApprovalEvidence }
  | { status: "declined"; reason: "user_declined" }
  | { status: "no_eligible_credential" };
```

Per the brief's API review (revision #1), `requestApprovalEvidence` returns
a discriminated outcome rather than throwing on user decline. Decline is a
routine outcome — the caller's modal returned `"decline"` — and the
"no eligible credential" rejection from the server is similarly routine.
Genuine errors (network failure, browser refusing the authenticator with
`NotAllowedError`, malformed server response, other approval-domain reasons)
still throw; the demo's existing `instanceof Error && err.name ===
"NotAllowedError"` and `isApprovalError` checks survive unchanged.

The library does **not** take ownership of the modal UI. The caller passes
an `onChallengeReceived(challenge) => Promise<"approve" | "decline">`
callback that decides the in-modal approve/decline. The caller also passes
the `request` function (same shape as the SDK's `Client["request"]`); the
library does not own the MCP transport.

## Demo migration

- `server/src/index.ts` keeps its full tool registry (execute lambdas, JSON
  inputSchema, argsSchema, describe), instantiates the gate with the demo's
  RP/origin/user values from `@mcp-sec/shared`, registers `place_trade`
  with the gate, plumbs the three approval methods to `gate.handle*`, and
  calls `gate.verifyApprovalForCall` inside its `tools/call` handler. The
  /trades and /credentials HTTP endpoints, the trade log, and the HTTP
  server stay in the demo.
- `client/src/main.ts` instantiates an `approvalClient`, calls
  `approvalClient.enroll()` from the enroll button handler, and calls
  `approvalClient.requestApprovalEvidence` from the form submit handler.
  The modal UI, the log, the form, and the credentials list stay in the
  demo. `@simplewebauthn/browser` is no longer a direct demo dep; it
  comes in transitively through the library.
- `@mcp-sec/shared` shrank to the demo's deployment configuration
  (`RP_ID`, `RP_NAME`, `EXPECTED_ORIGIN`, `USER_HANDLE`, `USER_NAME`,
  `USER_DISPLAY_NAME`) and the `place_trade` tool types. Everything else
  moved to the library's shared subpath. Two transitive deps
  (`canonicalize`, `@simplewebauthn/browser`) dropped from
  `shared/package.json`.

## Tests

All 11 tests stayed where they were and didn't change shape — they spin
up `startServer(0)` from the demo and exercise the protocol end-to-end.
The demo now uses the library, so the same tests are now end-to-end
through the library's public API.

`server/test/helpers.ts` switched its protocol-vocabulary import from
`@mcp-sec/shared` to `mcp-verified-approval/shared` (`EXPECTED_ORIGIN`
still comes from the demo's `@mcp-sec/shared`). No new test file. No
backdoor into library internals — the existing tests reach what they
need through the public `startServer` + MCP request surface.

`assertion.test.ts` test #5 (counter regression) uses the *emulator's*
`PasskeysCredentialsMemoryRepository` — that's emulator-internal, not
server-internal — so the public API was not extended for the test.

```
Test Files  3 passed (3)
     Tests  11 passed (11)
```

## Risks the brief flagged — verification

1. **Canonicalization identity.** Both server and client now import
   `canonicalArgs` from the same module path
   (`mcp-verified-approval/shared`). The demo's `@mcp-sec/shared` no
   longer exports a `canonicalArgs` at all, so the only way for either
   side to produce canonical JSON is through the library's single
   function. The argument-tampering test
   ([assertion.test.ts:64-80](../server/test/assertion.test.ts#L64-L80))
   continues to fire `argument_hash_mismatch` specifically — and that
   reason is only reachable via the server-side recompute path that
   uses the same `canonicalArgs`.
2. **Atomic consume.** The check-and-set on `stored.consumed` remains
   inside `verifyApprovalForCall` and remains synchronous within one
   event-loop tick — see
   [mcp-verified-approval/src/server/index.ts:330-334](../mcp-verified-approval/src/server/index.ts#L330-L334).
   The Phase 1 atomicity comment moved with the code. The replay test
   continues to fire `challenge_consumed`.
3. **Action-hash binding semantics.** The wire challenge is still
   `base64url(nonce || actionHash)`; the construction is in
   [server/index.ts:243-251](../mcp-verified-approval/src/server/index.ts#L243-L251).
   The argument-tampering test continues to fail with
   `argument_hash_mismatch` (not an upstream error), confirming the
   action-hash recompute path is the one rejecting.
4. **Authenticator-class policy enforced at both interception points.**
   Issuance-time filter:
   [server/index.ts:215-222](../mcp-verified-approval/src/server/index.ts#L215-L222).
   Verify-time recheck:
   [server/index.ts:300-308](../mcp-verified-approval/src/server/index.ts#L300-L308).
   `assertion.test.ts` test #4 covers both paths and remains green.
5. **Counter monotonicity / Apple counter-zero edge case.**
   `verifyAuthenticationResponse` is called with the stored counter
   unchanged from Phase 3; SimpleWebAuthn's permissive behaviour for
   counter=0 credentials is preserved.
   `assertion.test.ts` test #5 still uses an emulator credential
   (with controllable counter) for that reason.
6. **Challenge / enrollment / credential stores kept distinct.**
   Inside the gate, `challenges`, `pendingEnrollments`, and the
   pluggable `credentialStore` are three separate concerns. The
   in-memory implementation of `credentialStore` is the only one
   shipping in 4b; persistent backends can replace just that interface
   without touching the other two.

## What's intentionally not in 4b

- No npm publish; `version: "0.0.0"`.
- No README for external users — the SEP and this verification report
  are the documentation surfaces.
- No persistent `CredentialStore` implementation.
- No new public APIs beyond what's needed to migrate the demo.
- No production hardening (rate limiting, log redaction, metrics).
- No multi-package split — single package, subpath exports.
- No SEP draft writing (Phase 4c).

## Manual hardware verification — pending user action

The brief requires "a real trade signed by a real credential succeeds
end-to-end through the library" before tagging the phase complete. The
agent cannot perform this step. The procedure:

1. **Stop any running dev server on port 3030** (the agent observed
   `EADDRINUSE: 3030` while attempting an automated boot check; the
   port is held by an unrelated process — likely a pre-extraction dev
   server still running from a previous session).
2. From repo root:
   ```
   git checkout phase-4b-library-extraction
   npm run dev
   ```
   The server should print the Phase 4b banner with `port: 3030`,
   `tools: place_trade  (verified-approval: place_trade[cross-platform])`,
   `methods: approval/challenge/create, approval/enroll/begin,
   approval/enroll/finish, tools/list, tools/call`.
3. Open `http://localhost:5173` in Safari or Chrome. The status pill
   should say `connected` and the credentials section should reflect
   the in-memory state (empty after a fresh server start; a Phase 3
   credential survives client reload but not server restart, so a
   fresh enrollment is the simplest path).
4. If no credential is present, click **Enroll for approvals** and
   complete the OS passkey ceremony.
5. Fill out the trade form (e.g. `AAPL buy 10 @ 150.50`) and submit.
   The approval modal should display the action description verbatim
   (this is the library's `describeTrade` output via `gate.describe`).
6. Click **Approve**. Complete the OS passkey ceremony.
7. Confirm the log shows `trade ok  tradeId=… executedAt=…`.
8. Verify on `http://localhost:3030/trades` that the trade is recorded.

If all eight steps complete without protocol-level errors, Phase 4b is
done. Tag `phase-4b-complete` and merge to main.

## Status

- **Automated:** 11/11 tests green; `mcp-verified-approval/`,
  `@mcp-sec/shared`, and demo `server/`/`client/` all build and bundle.
- **Manual:** hardware end-to-end pending user execution per the
  procedure above.
- **Branch:** `phase-4b-library-extraction`, four commits
  (`phase-4b-step-{a,b,c,d}`), unmerged.
- **Tag:** not yet applied — wait for hardware verification.
- **Next:** Phase 4c (SEP draft writing) — not started, per brief.
