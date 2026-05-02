# Design Decisions

## `_meta` over `annotations` for `verifiedApproval/required`
- `annotations` is defined by the MCP spec as advisory; our field is normative.
- `_meta` is `z.record(z.string(), z.unknown())` — the spec-sanctioned extension namespace.
- Putting normative fields in an advisory family creates spec ambiguity that we'd have to argue around.
- Bonus: no SDK schema-strip workaround needed.

## RFC 8785 (JCS) for argument canonicalization
- `canonicalize@3.0.0` by Erdtman, author of RFC 8785 itself.
- Pure ESM, zero runtime deps, works in Node and browser bundles.
- Both server and client must hash identically; shared helper enforces this.

## Stub evidence in Phase 1
- Phase 1 deliberately uses `{ method: "stub", challengeId, userConfirmed: true }` rather than real signatures.
- Goal is to debug protocol shape independently of WebAuthn integration.
- Real WebAuthn ceremony arrives in Phases 2–3.

## Phase 2 carry-forward
- Split `invalid_challenge` into specific reasons (`consumed`, `expired`, `unknown`, `wrong_tool`) so tests can assert the precise invariant. Today the same reason fires for four distinct conditions, which works under current TTL but is fragile.
- When a second annotated tool exists, gate approval enforcement on `_meta` lookup at the call-handler entry point, not on hardcoded tool name. Today the approval logic lives inside the `place_trade` branch, so the bug class is structurally absent — but adding a second annotated tool would require remembering to wire it in. Refactor to `Map<name, { _meta, handler }>` and check `_meta?.[VERIFIED_APPROVAL_META_KEY] === VERIFIED_APPROVAL_VERIFIED` centrally.

## `_meta` for `approvalEvidence` on `tools/call`
- Symmetric with the tool-side `_meta` placement: extension fields live in `_meta`, period.
- The MCP spec already uses this pattern for its own extensions: `progressToken` and `io.modelcontextprotocol/related-task` are namespaced keys on the request-side `_meta`. We layer `verifiedApproval` the same way.
- Mechanism: `CallToolRequestSchema.params._meta` is a typed object with `z.core.$loose` passthrough, so unknown extension keys round-trip natively without modifying the SDK. (Note: this is different from the tool-listing `_meta`, which is `z.record(z.string(), z.unknown())` — both round-trip unknown keys, via different zod mechanisms.)
- Implementation: a small extension schema declares `_meta.verifiedApproval: ApprovalEvidenceSchema.optional()` with passthrough preserved, so the existing SDK-defined keys (`progressToken` etc.) still survive. ~5 lines, no SDK fork.
- Deletes the Phase 1 custom outer-`params` wrapper that was making `params.approvalEvidence` survive at the top level.

## Authenticator class policy: capability filter, not use-time guarantee

**What this proposal delivers (load-bearing claims):**
- Argument-binding: the assertion's signature is cryptographically bound
  to (toolName, canonicalArguments, serverId) via the challenge field.
- Freshness: per-call nonce, 60s TTL, server-side single-use enforcement.
- Single-use: server consumes challenges atomically; replay attempts
  reject with `challenge_consumed`.
- Capability filtering: credentials whose transports advertise only
  `["internal"]` are excluded from eligibility for tools requiring
  `cross-platform`. This correctly bars same-device-only credentials.

**What this proposal does NOT deliver:**
- A guarantee that the user's signing gesture occurs on a display surface
  outside the client's trust boundary. With synced-credential providers
  (iCloud Keychain, Google Password Manager, etc.), a credential whose
  transports advertise `["hybrid", "internal"]` is locally usable on the
  client device; the OS picker chooses the local presentation path
  regardless of server-side hints.
- Display-tampering resistance for synced credentials. A compromised
  client driving the local presentation flow can display one action
  description while the underlying signature certifies the
  argument-bound hash — defended only at the cryptographic level
  (the user signed for *this exact action hash*), not at the user-
  understanding level (the user *saw* this action).

**Empirical finding (Phase 4 mitigation 1, 2026-05-02):** WebAuthn L3
`hints: ["hybrid"]` is a no-op on macOS 26.4.1 with Safari 26.4 and
Chrome 147. Apple's system picker presents the local credential
regardless of the hint. See verification/phase-4-mitigation-1.md.

**Spec field retained:** `_meta.verifiedApproval.authenticatorClass`
remains in the proposal as a capability filter. Tools opting into
`platform` accept any enrolled credential (including same-device);
tools defaulting to `cross-platform` exclude `["internal"]`-only
credentials but cannot exclude synced credentials presented locally.
The SEP documents this as a capability check, not a use-time
guarantee, and lists at-sign-time transport enforcement as future
work that requires platform-side changes.

**Future mitigations (open spec questions, not v1):**
- Per-call attestation that includes the transport actually used at
  sign-time. Not currently exposed by the WebAuthn assertion response.
- Out-of-band confirmation channel (push to a registered phone app)
  that does not depend on the assertion being on a separate device.
- Cross-platform agreement on a stricter `hints` semantics that
  platforms commit to honoring.

These are appropriate for v2 of the proposal once the v1 properties
are deployed and reviewers have engaged.

## Tool-side `_meta` unification (Phase 3, supersedes Phase 1)

- **Phase 1 used a flat slash-key on the tool side**: `tool._meta["verifiedApproval/required"] = "verified"`. The request side already used a nested object: `params._meta.verifiedApproval = { method, challengeId, ... }`. The asymmetry was the first thing a careful reviewer would notice.
- **Phase 3 unifies on nested.** Both sides now address the verified-approval extension under the same key `"verifiedApproval"` under `_meta`; the value differs by side:
  - tool side: `{ required: "verified", authenticatorClass?: "cross-platform" | "platform" }`
  - request side: `ApprovalEvidence` (the assertion)
- **Why nested over flat slash-keys:** the namespace hosts multiple fields per side (required + authenticatorClass on the tool; method + challengeId + response on the request). Nesting them under one key reads as a single namespace rather than as N orthogonal flat keys that happen to share a prefix.
- **Wire-format break.** Tool listings produced before the migration (Phase 1/2 scripts, fixtures) need updating. There is no compatibility shim; the server emits only the nested form. Folded naturally into Phase 3's centralized `_meta` lookup refactor (Phase 1 verification carry-forward #2).

## Action-hash byte-order specification (Phase 3)

The challenge bytes that the WebAuthn authenticator signs over are produced by:

```
actionHashBytes = SHA-256( utf8(toolName) || 0x00 || utf8(canonicalArgsJson) || 0x00 || utf8(serverId) )   // 32 bytes
nonceBytes      = crypto.randomBytes(32)                                                                    // 32 bytes
wireChallenge   = base64url( nonceBytes || actionHashBytes )                                               // 86 b64url chars
```

- **Order: `nonce || actionHash`, NOT `actionHash || nonce`.** Picked once and pinned because either order is defensible but a future re-implementer guessing wrong silently breaks signature verification (clients produce bytes the server doesn't accept). Consumers MUST split the decoded 64 bytes as `[nonce: 32][actionHash: 32]`.
- **Why both halves:** nonce gives freshness (defends against replay across challenges), action hash binds this signature to the specific canonicalized argument string (defends against argument substitution after signing). The server stores both halves separately in the pending-challenge entry; at verify time `expectedChallenge` pins the wire bytes verbatim AND the server independently recomputes the action hash from the actual call arguments and compares (defense in depth — mismatch surfaces as `argument_hash_mismatch`).
- **`canonicalArgsJson`:** RFC 8785 (JCS) over the tool's arguments; produced by the shared `canonicalArgs(args)` helper. Both sides MUST canonicalize identically — Phase 3 keeps server as the only computer of the action hash, but Phase 4+ may choose to have the client compute it (e.g. for offline pre-verification).
- **`serverId`:** a per-server identifier baked into the hash so a challenge issued by server A cannot be replayed against server B even if both have enrolled the same credential. Phase 3 hardcodes `"phase-3-dev-server"`. Phase 4+ may derive from a more durable identity (e.g. the server's first-published OAuth issuer URL) once one exists.

## Discriminated-union evidence schema (Phase 3, "stub" removed)

- **Phase 1 stub variant gone.** The wire schema `ApprovalEvidence` is now `{ method: "webauthn", challengeId, response: AuthenticationResponseJSON }`. There is no production code path that accepts unsigned approval. Tests use real WebAuthn assertions produced by `nid-webauthn-emulator`.
- **Schema:** single-variant `z.object({ method: z.literal("webauthn"), ... })` today. Switch to `z.discriminatedUnion("method", [...])` when a second method materializes (delegated session, hardware-token-only, etc.). Keeping the literal-not-string tagged shape now means that future expansion is an additive change rather than a type widening at every read site.