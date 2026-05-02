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

## Meta-key rename to `io.modelcontextprotocol/verified-approval` (Phase 4c, 2026-05-02)

- **What changed.** The two shared `_meta` namespace constants — `VERIFIED_APPROVAL_TOOL_META_KEY` (read at `tool._meta`) and `VERIFIED_APPROVAL_REQUEST_META_KEY` (read at `params._meta`) — both moved from the bare string `"verifiedApproval"` to the reverse-DNS form `"io.modelcontextprotocol/verified-approval"`. The two constants remain distinct symbols sharing a string value, per the Phase 4b extraction. JSDoc and comments quoting the old key were updated in the same commit.
- **Why now.** The rename anticipates SEP submission. The MCP spec's `_meta` namespace already mixes bare keys (`progressToken`) for spec-defined fields and reverse-DNS keys (`io.modelcontextprotocol/related-task`) for namespaced extensions. A non-spec extension belongs in the reverse-DNS form; renaming pre-submission means reviewers see the expected form, and the reference implementation does not need a key migration after acceptance.
- **Asymmetry: capability key stays bare.** The companion capability declaration in `initialize` (advertised when a server supports the verified-approval extension) remains the bare string `verifiedApproval`, parallel to how the elicitation spec advertises the bare `elicitation` capability. The split is deliberate: namespaced keys for `_meta` extension fields (collision prevention across extensions a server may host), bare keys for capability declarations (which name spec-recognized features and form a closed enumeration the spec controls).
- **Scope of this commit.** Only the protocol-level key string changed. Library API names (`createApprovalGate`, `verifyApprovalForCall`, etc.), the package name (`mcp-verified-approval`), the RPC method names (`approval/enroll/begin`, `approval/enroll/finish`, `approval/challenge/create`), and the JSON-RPC error code (`-32001`) are unchanged. All 11 tests pass without modification.
- **Earlier references.** The Phase 1 verification reports under `verification/` and historical entries above this one continue to refer to the pre-rename key. Those are point-in-time records and are not retroactively edited; this entry is the source of truth for the current key form.

## Capability declaration placement under `extensions` (Phase 4c, 2026-05-02)

- **What changed.** The reference implementation now declares the verified-approval capability under `capabilities.extensions.verifiedApproval` rather than as a bare top-level `capabilities.verifiedApproval`. The capability key inside `extensions` remains BARE (`verifiedApproval`), matching the brief's asymmetry decision. The library helper `getApprovalCapabilityDeclaration()` returns `{ extensions: { verifiedApproval: {} } }`; the demo server spreads it into its `initialize` capability declaration.
- **Why not bare top-level.** The SDK 1.29.0's `ServerCapabilitiesSchema` is `z.object({ ... })` with a closed list of known capability fields (`experimental`, `logging`, `completions`, `prompts`, `resources`, `tools`, `tasks`, `extensions`). It does not use `.passthrough()` or `.catchall()`. A bare top-level `verifiedApproval` key is dropped by the SDK's client-side parse during `Client.getServerCapabilities()`. The server still emits the bare key on the wire (the server's `_oninitialize` returns capabilities verbatim), but clients using the SDK Client API never see it.
- **Why `extensions` is the right slot.** The SDK schema explicitly defines `extensions: z.record(z.string(), AssertObjectSchema).optional()` with the doc comment "Extensions that the server supports. Keys are extension identifiers (vendor-prefix/extension-name)." This is the spec-designed namespace for non-spec capabilities. Placing the capability there is using the existing extension point correctly, not a workaround for a parse-strip.
- **Asymmetry decision survives.** The "bare for capabilities, namespaced for `_meta`" rule from the prior entry still holds. Capabilities live in a closed namespace (the spec or the SDK's `extensions` slot controls what's recognized); `_meta` is an open namespace where collision prevention requires reverse-DNS. Bare *within* `extensions` is correct: `extensions` is itself the closed namespace the SDK provides for extension capabilities, the same way the top-level `capabilities` object is the closed namespace for spec capabilities.
- **The earlier "compare elicitation" framing was imprecise.** The prior entry pointed to elicitation as a precedent for bare top-level capability declaration. `elicitation` is bare top-level in the SDK, but it's a *client* capability (in `ClientCapabilitiesSchema`), not a server one — clients advertise elicitation support to servers. Server-side extension capabilities don't have an analogous spec-recognized bare slot today; `extensions` is what they have. The asymmetry conclusion is unchanged; the analogy used to support it was off.
- **Forward compatibility.** If the verified-approval proposal is accepted into the official MCP spec, the SDK will at that point add `verifiedApproval` to `ServerCapabilitiesSchema` as a known field, and the wire shape MAY shift to bare top-level. Library consumers should treat `getApprovalCapabilityDeclaration()` as the source of truth and not encode the placement themselves; a future release of the library can update the helper without consumers needing to change their wiring.

## Enrollment-time security tightening (Phase 4c, 2026-05-02)

Pre-§4.4-drafting alignments. The §4.4 brief asked the spec text to assert two enrollment guarantees that the implementation did not yet provide; both library changes were made before §4.4 prose was drafted so the spec and the reference implementation lock together.

### User verification required at enrollment

- **What changed.** `handleEnrollBegin` sets `authenticatorSelection.userVerification: "required"` (was `"preferred"`); `handleEnrollFinish` passes `requireUserVerification: true` to `verifyRegistrationResponse` (was `false`).
- **Why.** A credential capable only of user-presence (UP) rather than user-verification (UV) should not enter the pool for an approval capability. The use-time path was already strict (`requestOptions.userVerification: "required"` at challenge issuance, `requireUserVerification: true` at assertion verify), but a UP-only credential could enroll and then fail every signing attempt — a worse failure mode than refusing enrollment. SEP §4.4.1's framing ("a presence-only gesture cannot enroll") required this tightening.
- **Compatibility.** All existing tests pass without modification: `nid-webauthn-emulator` defaults produce UV-set authenticator data when the registration options request UV. Hardware that reports as UP-only is excluded by design.

### Server-side rejection of already-enrolled credentials

- **What changed.** `handleEnrollFinish` now checks `credentialStore.get(credential.id)` after WebAuthn verification and before `put()`. If the credential is already enrolled, rejects with `approvalError("credential_already_enrolled", ...)`. New error reason added to the `ApprovalErrorReason` typed union in shared/index.ts.
- **Why.** The browser's WebAuthn-layer `excludeCredentials` enforcement is the first line of defense, but a malicious client can bypass it: with `attestation: "none"`, nothing in the registration response signs over `clientDataJSON`, so a captured registration response can be replayed against a fresh challenge by rewriting `clientDataJSON.challenge`. Without the server-side check, the replay would silently overwrite the existing credential record — including its stored counter — defeating counter-regression detection on subsequent assertions. SEP §4.4.2's "MUST reject registration if the credentialId is already enrolled" required this defense-in-depth.
- **Test coverage.** New test in `server/test/enrollment.test.ts` exercises the bypass scenario directly: enroll a credential cleanly, then submit the same registration response to a fresh challenge with `clientDataJSON.challenge` rewritten to match. Server rejects with `credential_already_enrolled`. 13 tests green.
- **Error-reason placement.** `credential_already_enrolled` lives in the `ApprovalErrorReason` typed union alongside the other discriminator reasons. The two pre-existing enrollment-domain reasons (`no_pending_enrollment`, `verification_failed`) remain inline on `approvalError`'s parameter type; harmonizing them with the typed union is a separate cleanup outside this commit's scope.

## Error reason enumeration alignment (Phase 4c, 2026-05-02)

Pre-§4.6-§4.11-drafting library tightening. Four additions to the `ApprovalErrorReason` typed union — two splits that introduce new behavior, two promotions of pre-existing inline reasons. SEP §4.10 enumerates the typed union directly, so spec text and reference implementation lock together.

- **`unsupported_method` (split, new behavior).** Previously, evidence whose `method` was not the literal `"webauthn"` was rejected with `missing_evidence` ("missing or malformed"). Splitting this out lets clients distinguish "client bug, evidence absent or wrong shape" from "client speaks an approval method this server doesn't understand." The split is forward-compat groundwork: when a second `method` value (e.g., delegated session, hardware-token-only) is added to the spec, clients on older servers receive a recognizable reason and can fall back rather than treating the failure as a generic protocol violation.
- **Schema loosening for `unsupported_method`.** Reaching the runtime check required loosening `ApprovalEvidenceSchema.method` from `z.literal("webauthn")` to `z.string()`, and the corresponding `ApprovalEvidence.method` type from `"webauthn"` to `string`. Otherwise the wrong-method case is rejected by the SDK's JSON-RPC schema parse (with `-32602`) before reaching the gate's runtime discriminator. The type comment notes that today's only conformant value is `"webauthn"` and that the schema should switch to a `z.discriminatedUnion("method", ...)` when a second method materializes.
- **`tool_not_approved_required` (split, new behavior).** Previously, `approval/challenge/create` for a tool name not registered with the gate (either unknown to the demo's MCP server, or known but not approval-annotated) returned generic JSON-RPC error `-32602` ("Invalid params"). Promoting this to an approval-domain reason lets clients distinguish "this tool doesn't require verified approval" from other invalid-params cases. Both branches of the existing check (`!tool` and `tool.toolMeta.required !== VERIFIED_APPROVAL_REQUIRED`) collapse into the single approval-domain reason — from the gate's perspective, both mean "this tool is not registered as approval-required."
- **`no_pending_enrollment` (promotion, behavior unchanged).** Was inline on `approvalError`'s parameter union; now in the typed enum. Emitted by `handleEnrollFinish` when no `approval/enroll/begin` was called or its challenge expired. The promotion lets clients discriminate against this reason via the typed `ApprovalErrorReason` rather than parsing the human-readable message.
- **`verification_failed` (promotion, behavior unchanged).** Same — was inline, now typed. Emitted by `handleEnrollFinish` when `verifyRegistrationResponse` from `@simplewebauthn/server` throws or returns `verified: false`.

The `approvalError` function's parameter type narrows from `ApprovalErrorReason | "no_pending_enrollment" | "verification_failed"` to plain `ApprovalErrorReason`. Two new tests cover the behavior-changing splits (one in `assertion.test.ts` for `unsupported_method`, one for `tool_not_approved_required`); the two promotions are type-only changes covered by the existing enrollment-tampering tests. 15 tests green.

## Why introduce `serverId` rather than reference an existing MCP field (Phase 4c, 2026-05-02)

The §4.6 normative requirement that servers use a unique `serverId` raises a natural question: why doesn't the SEP reference an existing MCP field instead of introducing a new identifier?

**No existing MCP field is per-deployment unique.** The MCP base spec defines `serverInfo` in the `initialize` response with `{ name, version }` fields. Neither is designed to be unique across deployments — two independent installations of the same MCP server emit identical `serverInfo`. There is no spec-defined per-deployment identifier. The verified-approval proposal therefore has to introduce one.

**`serverId` is implementation-internal, not on the wire.** The serverId never appears as a transmitted JSON-RPC field. It is consumed only inside the action-hash computation `SHA-256(toolName || 0x00 || canonicalArgs || 0x00 || serverId)`. The wire surface area added by this SEP is one `_meta` annotation key, one capability key under `extensions`, three JSON-RPC methods, and one `_meta` field on `tools/call`. Adding a normative MUST about a value that is never transmitted is precedented (RFC 8785 itself does the same — it mandates how implementations canonicalize JSON without adding wire fields), and a maintainer reviewing wire-protocol expansion correctly sees no expansion here.

**Why the MUST exists.** Without uniqueness, two servers using identical `serverId` values produce identical action hashes for identical (toolName, arguments) tuples. A challenge issued by server A could be replayed against server B if both expose a tool with that name. The "constant default values are non-conformant" clause is what closes the door on implementers reading the original "implementation-defined" wording and hardcoding `"my-server"` or `"mcp-default"`.

**Future spec convergence.** If the MCP base spec ever adopts a `serverInfo.uri` or similar field providing unambiguous per-deployment identity, §4.6 could reference it directly rather than leaving `serverId` implementation-defined. Until then, the proposal carries the MUST and recommends three suitable derivation strategies (OAuth issuer URL, stable URL identifier, persisted UUID).