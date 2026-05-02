# Roadmap & Status

## Phases

### Phase 0 — Scaffolding ✅ Complete
**Tag:** `phase-0-complete`

End-to-end MCP loop with no security: server with `place_trade` tool, browser client that calls it, both sides talking over Streamable HTTP. Verified loop, error framing, CORS preflight, stateful sessions, in-memory clear on restart.

### Phase 1 — Protocol skeleton ✅ Complete
**Tags:** `phase-1-complete` (sibling-field shape), `phase-1-meta-migration` (`_meta` shape)

The verified-approval ceremony wired through MCP with stub evidence — no cryptography. Three security properties tested and green:
1. Argument-binding: tampered arguments after challenge issuance fail with `argument_hash_mismatch`.
2. Single-use: replayed challenges fail with `invalid_challenge` (consumed branch).
3. Freshness: 60s TTL with 30s reaper.

Evidence flows through `params._meta.verifiedApproval` — same namespace as the tool-side `_meta.verifiedApproval/required` flag. Schema preserves SDK-defined keys (`progressToken` etc.) via passthrough.

Verification reports: `verification/phase-1.md`, `verification/phase-1-meta-migration.md`.

### Phase 2 — WebAuthn enrollment 🔄 Next
Add real WebAuthn registration. New methods `approval/enroll/begin` and `approval/enroll/finish`. Server stores `(credentialId, publicKey, signCount, userHandle)` in memory. Client gains an "Enroll for approvals" button that triggers a registration ceremony with hybrid transport (Mac shows a QR, iPhone scans, passkey created and synced to iCloud Keychain). Credential persists across page reloads, not server restarts.

**Deliberately does not change tool-call behavior.** Tool calls still use stub evidence. Enrollment and assertion are kept in separate phases because both are independently fiddly to debug.

### Phase 3 — WebAuthn approval with argument binding ⏳ Pending
The security-critical phase. Replace stub evidence with real per-call signatures.
- Server's `approval/challenge/create` returns a `PublicKeyCredentialRequestOptions` with the challenge encoding both nonce and action hash.
- Client invokes `navigator.credentials.get()`. Browser orchestrates with iPhone via hybrid transport. iPhone shows Face ID prompt with the action description. Phone signs.
- Server verifies via `@simplewebauthn/server`'s `verifyAuthenticationResponse`, recomputes action hash from actual call, checks it matches, checks `signCount` is monotonic.
- `ApprovalEvidenceSchema` becomes a discriminated union: `z.literal("stub")` (legacy, for tests) plus `z.literal("webauthn")` (the real method).
- Failure-path tests added: tampered arguments after signing → reject; replay → reject; missing evidence → reject. These tests are the eventual SEP's test vectors.
- **Authenticator-class policy enforced.** Filters `allowCredentials` by transport class during challenge issuance, and rejects assertions from ineligible credentials at verify time. The Phase 2 multi-credential setup (iPhone hybrid + Chrome internal) provides the test surface for both eligible-accept and ineligible-reject paths.

### Phase 4 — Reference and SEP draft 🔄 In progress
Make the working code into something others can read, run, and learn from. Then write the actual SEP, under the narrowed-claim framing established by mitigation-1 investigation.

**Sub-phase 4a — Mitigation investigation ✅ Complete (2026-05-02).** Tested `hints: ["hybrid"]` on macOS 26.4.1 with Safari 26.4 and Chrome 147. Result: hint is a no-op; Apple's system picker presents the local credential regardless. SEP framing resolved: the proposal claims argument-binding + freshness + single-use; authenticator-class is documented as a capability filter, not a use-time guarantee. See `verification/phase-4-mitigation-1.md` and the revised `DECISIONS.md` "Authenticator class policy" entry. Tag: `phase-4-mitigation-1-complete`.

**Sub-phase 4b — Library extraction ⏳ Pending.** Extract approval logic into a clean library (`mcp-verified-approval` with `server` and `client` subpackages).

**Sub-phase 4c — SEP draft writing ⏳ Pending.** Now unblocked by 4a's framing decision.
- Write `SPEC.md` (or fold directly into `sep-draft/SEP-DRAFT.md`) using the eight required SEP sections. Normative MUST/SHOULD language.
- Write `THREAT_MODEL.md` covering rogue agent, prompt injection, replay, downgrade, argument substitution. Include the documented residual display-tampering risk for synced credentials and the future-mitigations list from `DECISIONS.md`.
- Write `LIMITATIONS.md` covering known gaps: recovery, headless contexts, batched approval, cross-server credential reuse, at-sign-time transport enforcement.
- Demo video, README setup instructions, runnable failure-path tests as examples.

### Phase 5 — Engagement (overlaps Phase 3+) ⏳ Pending
- Send peer-tone message to Sebastian Mart re: server-side policy enforcement SEP.
- Open a Discussion on `modelcontextprotocol/specification` describing the gap and direction. Do this *before* the SEP PR — community discussion precedes formal submission per the SEP guidelines.
- Identify 2–3 sponsor candidates from `MAINTAINERS.md`, especially those who've engaged with security or extension proposals.
- Once Phase 4 ships and discussion has had real engagement, open the SEP PR and tag a sponsor candidate.

## Pending tasks (cross-phase)

### To do during or alongside Phase 2

- [ ] Split `invalid_challenge` into `consumed`, `expired`, `unknown`, `wrong_tool` — current single-reason check works under 60s TTL but is fragile. Test #2 caveat from Phase 1 verification.
- [ ] Refactor approval check from hardcoded tool-name branch to centralized `_meta` lookup, since Phase 2 is where a second method (enrollment) starts asking "which tools require this?" Architecture nit from Phase 1 verification test #5.

### Pre-Phase-4 community homework (deferred — was offered, declined for momentum)

- [ ] Join MCP Discord. Lurk in `#general`, `#seps`, security-related channels. Calibrate tone.
- [ ] Read 2–3 existing SEPs from `seps/` directory: one accepted/final, one in-review, ideally one touching security or `_meta`.
- [ ] Skim `MAINTAINERS.md`, identify 2–3 sponsor candidates whose area is security/extensions.
- [ ] Pull SEP template into `sep-draft/SEP-DRAFT.md`.
- [ ] Send peer message to Sebastian Mart.
- [ ] Skim discussions #561, #668, #594, #581 (cited by Theaxiom in SMCP RFC as prior demand signal).

These are deferred but not abandoned. Do them before Phase 4 at the latest.

### Open design questions (for spec, not implementation)

- 📌 **Future Work: at-sign-time transport enforcement.** The Phase 2/3 framing of "cross-platform required" as a use-time display-surface separation guarantee was empirically narrowed by Phase 4 mitigation 1 (see `verification/phase-4-mitigation-1.md`). `hints: ["hybrid"]` is a no-op on Apple platforms today. The capability-filter framing is what the v1 SEP claims; at-sign-time transport enforcement requires platform-side changes (per-call attestation of which transport was actually used, or stricter `hints` semantics) and is appropriate for v2.
- [ ] Headless agent contexts (LangGraph, Agent SDK, CI runners). Refuse-to-run is the simple answer; delegated-approval session is the harder, more useful answer.
- [ ] Recovery flow when user loses phone. Standard WebAuthn recovery patterns apply but need explicit treatment in the spec.
- [ ] Batched approval for multi-step plans. Latency story is bad without it. Argument-binding gets harder when the call hasn't been precisely specified yet.
- [ ] Credential rotation and re-enrollment.
- [ ] Multi-party countersignature flows (manager + employee both must sign).

## Decisions log

See `DECISIONS.md`. Major decisions to date:
1. `_meta` over `annotations` for the tool-side requirement flag.
2. RFC 8785 / JCS for argument canonicalization.
3. Stub evidence in Phase 1 (debug protocol shape independently of WebAuthn).
4. `_meta` on the request side for evidence too — symmetric placement, follows SDK precedent (`progressToken`).