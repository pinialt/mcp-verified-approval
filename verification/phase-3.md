# Phase 3 verification

Reference commit: `1d66e13` (`phase-3-step-d: client assertion ceremony and eligibility-aware UI`)
Tag: `phase-3-complete`

## What Phase 3 is

Phase 3 of the MCP verified-approval reference implementation replaces
the stub evidence used in Phases 1–2 with real WebAuthn assertions
bound to the specific tool call's canonicalized arguments. After this
phase the proposal's central claim — *"a compromised client cannot
forge approval for a specific high-sensitivity tool call"* — is
demonstrably true rather than asserted, both at the unit-test level
(via a software authenticator producing real CTAP responses) and on
real hardware (an iPhone passkey synced via iCloud Keychain).

The protocol changes in Phase 3:

1. **`approval/challenge/create`** now returns a full
   `PublicKeyCredentialRequestOptionsJSON` blob alongside the existing
   `challengeId` / `displayText` / `expiresAt` siblings. The wire
   challenge field carries `base64url(nonce || actionHash)` — 32 bytes
   of fresh randomness for replay protection plus the 32-byte
   SHA-256(toolName ‖ canonicalArgs ‖ serverId) that binds the
   signature to this specific call. (Byte-order specification in
   `docs/DECISIONS.md`.)

2. **Authenticator-class policy** is enforced on both sides. The tool's
   `_meta.verifiedApproval.authenticatorClass` field declares the
   required class (`"cross-platform"` or `"platform"`); the server
   filters `allowCredentials` at issuance time and re-checks at verify
   time.

3. **`tools/call`** verifies the assertion via
   `verifyAuthenticationResponse`, recomputes the action hash from the
   actual call arguments (defense in depth, separate from the SDK's
   `expectedChallenge` check), updates the credential's stored counter,
   then atomically consumes the challenge before executing the tool.

4. **The "stub" evidence variant is gone** from the wire entirely. The
   schema accepts only `{ method: "webauthn", challengeId, response }`.
   Phase 1's three protocol-shape tests were rewritten on the
   emulator-driven assertion path during this phase.

5. **Tool-side `_meta` namespace unified** with the request-side: both
   sides now address the verified-approval extension under a single
   key `verifiedApproval`, with a nested object as the value. Phase 1's
   flat slash-key (`verifiedApproval/required`) was the asymmetric
   shape; Phase 3 fixed it. Wire-format break handled in the centralized
   `_meta` lookup refactor (Phase 1 verification carry-forward #2).

## Carry-forwards now resolved

- **Phase 1 verification, Finding 2** — *"split `invalid_challenge`
  into specific reasons so tests can assert the precise invariant"*.
  Done. Replaced with `challenge_unknown` / `challenge_expired` /
  `challenge_consumed` / `challenge_wrong_tool`. The replay test now
  asserts `challenge_consumed` specifically, closing the test-quality
  caveat that under a low TTL the test could silently pass for the
  wrong reason.
- **Phase 1 verification, Finding 5** — *"gate approval enforcement on
  `_meta` lookup at the call-handler entry point, not on hardcoded
  tool name"*. Done. Server uses a `Map<name, RegisteredTool>` registry;
  the call handler reads `tool.toolMeta.required` to decide whether to
  enforce and `tool.toolMeta.authenticatorClass` for the policy lookup.
  Adding a second annotated tool is now a one-line `TOOLS.set()` call.
- **Phase 2 verification, Finding 1** — *"`transports` must be treated
  as security-relevant in Phase 3, not as advisory metadata"*. Done.
  Both at challenge issuance (filtering `allowCredentials`) and at
  verify time (`authenticator_class_mismatch` defense-in-depth check),
  the server treats the credential's `transports` array as load-bearing.

## Test results — `npm test`

11 / 11 green:

- 3 phase-1 protocol-shape tests (`server/test/approval.test.ts`),
  rewritten on the emulator path, asserting on the new reason strings:
  - **happy path** — challenge → emulator-signed assertion → tools/call → trade
  - **argument tampering** — `quantity: 100` challenge, `quantity: 1000`
    call, evidence bound to original → `argument_hash_mismatch`
  - **replay** — same evidence twice → `challenge_consumed`

- 3 phase-2 enrollment tests (`server/test/enrollment.test.ts`),
  unchanged.

- 5 phase-3 assertion tests (`server/test/assertion.test.ts`):
  1. **happy path** — sanity-checks the wire challenge length is
     86 base64url chars (= 64 bytes = 32 nonce + 32 action hash),
     `userVerification: "required"`, non-empty `allowCredentials`,
     and a successful trade.
  2. **argument tampering** — same as Phase 1's tampering test, in the
     Phase-3 file too. Headline test: a compromised client cannot
     swap arguments after the user signed.
  3. **replay** — same evidence on a second call → `challenge_consumed`.
  4. **authenticator-class enforcement** — enrolls a credential
     advertising only `"internal"` transport. Verifies rejection at
     both possible interception points: at issuance
     (`no_eligible_credential` when no other creds exist), and at
     verification (`authenticator_class_mismatch` /
     `unknown_credential` when a malicious client tries to push an
     ineligible credential past the filter).
  5. **signature counter regression** — enrolls with
     `signCounterIncrement: 1`, does a successful first assertion
     (server stores `counter=1`), then directly mutates the emulator's
     internal `signCount` back to 0 via the credential repository.
     Second assertion produces `counter=1`; SimpleWebAuthn requires
     strictly greater than the stored value, so verify throws and we
     map to `signature_counter_regression`.

### Note: Apple synced passkeys and counter 0

`server/test/assertion.test.ts` documents in-line that the
counter-regression test cannot use an iPhone-synced passkey because
those report `counter: 0` forever (passkeys aren't required to
maintain a real counter; SimpleWebAuthn skips the check when the
stored counter is 0). The emulator gives us a controllable counter for
the unit test. For Apple-synced credentials in production, the
operative freshness guarantee is `challenge_consumed` (single-use),
not the counter; this is consistent with the WebAuthn spec's treatment
of multi-device credentials.

## Hardware test outcomes

Run on the same Mac Studio used in Phase 2. The user enrolled two
credentials and successfully placed a trade. `GET /credentials`
captured live during the verification run:

```json
[
  {
    "credentialId": "rb3sJVq12-FM",
    "transports": ["internal"],
    "createdAt": "2026-05-01T19:04:14.774Z"
  },
  {
    "credentialId": "zjvopqH2UW7k",
    "transports": ["hybrid", "internal"],
    "createdAt": "2026-05-01T19:05:09.466Z"
  }
]
```

Both credentials were created in same-device ceremonies on the Mac via
the OS password app — neither involved a QR code or the iPhone Camera
at enrollment time. The difference is *where the credential was
saved*:

| credentialId (truncated) | transports | enrollment ceremony |
|---|---|---|
| `rb3sJVq12-FM` | `["internal"]` | Mac password app, saved on this device only. The credential is bound to this Mac; the authenticator advertises only `internal` because it cannot be presented from anywhere else. |
| `zjvopqH2UW7k` | `["hybrid", "internal"]` | Mac password app, saved to iCloud Keychain. The credential ends up on the user's other Apple devices via iCloud sync; the authenticator advertises `hybrid` (cross-device use via Bluetooth pairing) AND `internal` (same-device use via Touch ID on this Mac, since the credential is present here too). |

This matches the pattern documented in
`verification/phase-2.md` Finding 3 — `transports` reflects use-time
capability, not enrollment provenance. Both credentials were enrolled
on the Mac; one is now usable from a separate device via iCloud sync,
the other isn't.

From the client log at trade time:

```
[19:06:24.799] authenticator response received (id zjvopqH2…SuTylY)
[19:06:24.800] submitting tools/call with webauthn evidence…
[19:06:24.813] trade ok  tradeId=92293f44-0d2d-418f-bf6a-83e5135afe8f
                          executedAt=2026-05-01T19:06:24.811Z
```

The `id` in the authenticator response (`zjvopqH2…`) matches the
iCloud-synced credential exactly. The Mac-only credential
(`rb3sJVq12…`) was enrolled and present in the credential map
throughout — but did not sign this assertion. The server's
`allowCredentials` filter at challenge issuance excluded the
`["internal"]`-only credential, so the OS passkey picker was
presented with only the iCloud-synced one. **The user's actual
gesture at sign time was Touch ID on the Mac**, not Face ID on the
iPhone — the iCloud-synced credential is locally available on the Mac
too (that's exactly what the `internal` half of its transports list
means), so the OS preferred the local biometric.

The server's `verifyAuthenticationResponse` validated the signature
against the stored public key, recomputed the action hash to confirm
argument-binding, atomically consumed the challenge, updated the
credential's counter, and executed the trade. The 13-millisecond gap
between "submitting tools/call with webauthn evidence" and "trade ok"
is end-to-end signature verification + action hash recomputation +
counter update + atomic consume + trade execution.

This is the right outcome for the *transport-class* policy as
implemented (the Mac-bound credential was correctly filtered out;
the cross-platform-capable credential was correctly accepted), but
see Finding 4 below — the threat-model property the policy was
supposed to enforce is not yet achieved by the transport check alone.

## What's intentionally not in Phase 3

- **No persistent storage.** Credentials and challenges still in
  memory. Phase 4+ may extract to a library and add a persistence
  interface.
- **No multi-user.** Single hardcoded `USER_HANDLE`.
- **No new tools.** `place_trade` is still the only annotated tool.
  The centralized registry makes adding more a one-line operation.
- **No batched approval, no per-session approval, no recovery flows.**
  All deferred to v2.
- **No library extraction.** Phase 4 territory.
- **No SEP draft writing.** Phase 4 territory; the spec is to be
  written *from* the working code, not in parallel with it.

## Findings carried into Phase 4

### Finding 1 — Counter check is largely inert against synced passkeys

Apple's iCloud Keychain-synced passkeys report `counter: 0` on every
assertion. SimpleWebAuthn correctly skips the strict-monotonic check
when the stored counter is 0 (the WebAuthn spec permits this; not all
authenticators maintain a counter). This means in production with
synced passkeys, `signature_counter_regression` will essentially
never fire — the operative replay defense is `challenge_consumed`.

This is fine and consistent with the spec, but the eventual SEP needs
to make it explicit: *the freshness/single-use guarantee for verified
approval is the server-side challenge consumption, not the
authenticator's sign counter*. The counter check is defense-in-depth
against authenticator cloning for credentials that *do* maintain one.

### Finding 2 — Tool-side `_meta` shape unification was the right call

Phase 1 used flat slash-keys on the tool side
(`"verifiedApproval/required": "verified"`) while the request side
already used a nested object (`verifiedApproval: { method, ... }`).
The asymmetry was the first thing a careful reviewer noticed, and was
called out in the Phase 2 verification's Finding 2 framing of the
authenticator-class question. Unifying on the nested shape during
Phase 3's centralized `_meta` lookup refactor cost ~10 lines on top of
the refactor that was happening anyway, and removed an
explanation-debt the SEP would otherwise have had to carry.

The lesson is small but worth recording: when the Phase 1 brief
chose the slash-key form, it was reasonable in isolation but
asymmetric with the request side. Phase 3 was the right time to
unify; doing it later (Phase 4 library extraction) would have meant
breaking published example code rather than just internal callsites.

### Finding 3 — `signCount` storage adds value mostly for non-synced authenticators

The Phase 3 server stores and updates the credential's counter on
every successful assertion. For synced passkeys this is largely
write-only (always 0). For hardware keys (YubiKey, etc.) it's
load-bearing. If Phase 4+ adds support for hardware keys as a separate
authenticator class, the counter check becomes meaningfully active
for that class and the test in `assertion.test.ts` test #5 stops being
purely-emulator territory.

### Finding 4 — Transport-class check does not enforce the threat-model property it was supposed to

This is the most important finding from the hardware run, and it
sharpens the Phase 2 Finding 3 from a use-time-vs-enrollment-provenance
caveat into a use-time-still-isn't-enough caveat.

`docs/DECISIONS.md` justifies the cross-platform-required policy with:

> The threat is *display tampering*. A compromised client controls the
> user's screen; if the user's gesture is on the same device, the user
> is approving what the client decided to display, which may not be
> what's actually about to execute. A separate device's display
> surface is outside the client's trust boundary.

The hardware test demonstrated that the current implementation does
NOT achieve this property. The user's sign-time gesture was Touch ID
on the Mac, even though the chosen credential advertises `hybrid`.
Because iCloud Keychain syncs the credential's private key to all the
user's Apple devices, the credential is *locally* usable on the Mac
via Touch ID — and the OS prefers the local biometric over a
cross-device pairing when both are available. The user never sees a
QR code; the iPhone is never involved at sign time; the gesture lands
on the same display surface the (hypothetically compromised) client
controls.

The transport-class filter is doing exactly what it's defined to do —
exclude credentials that *can only* be presented from this device. It
does not ensure that the credential *was* presented from a separate
device this time. The two are different properties, and the spec text
in DECISIONS.md was reaching for the second.

What this means for Phase 4 / the SEP:

1. **The transport-class check is necessary but not sufficient.** It
   correctly excludes credentials with no separation potential
   (`["internal"]` only) — that's load-bearing for the threat model.
   But for synced passkeys it doesn't deliver same-time-different-device
   separation.
2. **Possible mitigations to evaluate in Phase 4:**
   - Set `authenticatorAttachment: "cross-platform"` in the request
     options (currently we don't). This is a *hint* in the WebAuthn
     spec, not a requirement, so platforms may ignore it. Needs
     hardware verification to see whether Apple's picker excludes
     iCloud-synced platform-resident passkeys when this hint is set.
   - Require the `hybrid` transport to actually be the one used.
     WebAuthn's `AuthenticatorAttestationResponse` exposes
     `getTransports()` post-registration but the per-assertion
     transport that was actually used isn't surfaced to the RP. There
     may be authenticator-data flag bits or extensions that help, but
     this needs spec-level investigation.
   - Reframe the spec to acknowledge that "cross-platform" enforces a
     *capability* rather than a *use-time guarantee*, and document
     that the threat-model claim against display tampering requires
     additional out-of-band signal (e.g. the user's known habit of
     using a specific authenticator, secondary signals like network
     locality, attestation chains).
   - Drop the threat-model claim against same-device-display-tampering
     for synced-passkey installations and narrow the proposal's
     promise to "argument-binding + freshness + single-use," which
     all *are* delivered.
3. **The eventual SEP must not claim a property the implementation
   doesn't deliver.** This is the kind of overclaim that gets a
   proposal kicked back at review. The honest framing: argument-binding
   is fully verified; the user-presence-on-separate-device claim is a
   capability check today, not a use-time guarantee, and an open spec
   question for the SEP draft.

## Bottom line

Eleven tests green. The headline argument-binding property is fully
delivered: argument-tampered tool calls cannot succeed even when the
user did sign approval for a similar call (verified at the protocol
level by `assertion.test.ts` test #2; the same code path runs on
hardware). Replay protection is delivered through challenge
consumption (`challenge_consumed`), and is the operative freshness
guarantee given that synced passkeys' counter check is largely inert.
Transport-class filtering correctly excludes credentials with no
cross-device potential (`rb3sJVq12…` was enrolled, eligible neither
in `allowCredentials` nor at verify-time).

What is *not* fully delivered, despite Phase 3's earlier framing:
**use-time same-device display-tampering resistance**. Finding 4
above lays out the gap and the mitigation directions for Phase 4.
The hardware test demonstrated this explicitly — the sign-time
gesture was Touch ID on the Mac even though the chosen credential
advertises `hybrid`, because iCloud Keychain made the synced
credential locally usable.

Phase 3 is done as a *protocol* phase: the wire shape, the verification
pipeline, the failure-mode taxonomy, and the test surface are all in
place and runnable. Phase 4 has substantive spec work ahead of it,
beyond the planned library extraction and SEP draft writing — Finding
4 needs to be resolved (or its scope narrowed in the spec text) before
the SEP can honestly claim the security properties it sets out to
provide.
