# Phase 2 verification

Reference commit: `02665bb` (`phase-2-step-d: client enrollment UI`)
Tag: `phase-2-complete`

## What Phase 2 is

Phase 2 of the MCP verified-approval reference implementation adds real
WebAuthn enrollment. Before Phase 2, the system had a working approval
ceremony with stub evidence — the protocol shape was right, but
"approval" was a literal `userConfirmed: true` field anyone could
forge. Phase 2 adds the registration half of the WebAuthn ceremony:
the user enrolls one or more authenticators (passkeys), the server
stores their public keys, and a debug endpoint lists what's registered.
Tool-call behavior is unchanged — calls still flow with stub evidence.
Linking enrolled credentials to per-call approval is Phase 3.

Why enrollment and assertion are separate phases: both are
independently fiddly. WebAuthn registration involves RP-ID and origin
configuration, hybrid transport pairing with the user's phone, and
attestation parsing. WebAuthn assertion involves challenge
construction, argument-binding through the challenge field, and
signature verification with monotonic sign-count. Mixing the two in a
single phase makes failures harder to localize. Phase 2 establishes
the enrollment foundation; Phase 3 wires assertion on top of it.

## What was added

| Component | Where |
|---|---|
| `approval/enroll/begin` and `approval/enroll/finish` MCP request handlers | [server/src/index.ts](../server/src/index.ts) |
| In-memory credential store: `Map<credentialId, { credentialId, publicKey, counter, transports, userHandle, createdAt }>` | same file; cleared on server restart |
| Pending-challenge store keyed by `userHandle`, 5-minute TTL, swept by the existing reaper | same file |
| `GET /credentials` debug endpoint returning `{ credentialId, transports, userHandle, createdAt }` — public-key bytes intentionally not exposed even in dev | same file |
| Authenticator section in the UI: status badge ("not enrolled" / "enrolled (N credentials)"), "Enroll for approvals" button, enrolled-credentials list with `current` badge on most-recent, separate enrollment log | [client/index.html](../client/index.html), [client/src/main.ts](../client/src/main.ts), [client/src/style.css](../client/src/style.css) |
| Three vitest cases driven by `nid-webauthn-emulator` (Nikkei) as a software authenticator producing real CTAP responses through `verifyRegistrationResponse` | [server/test/enrollment.test.ts](../server/test/enrollment.test.ts) |

Hardcoded constants live in [shared/src/index.ts](../shared/src/index.ts):
`RP_ID = "localhost"`, `EXPECTED_ORIGIN = "http://localhost:5173"`,
`USER_HANDLE = "phase-2-dev-user"`. These are passed through to
`verifyRegistrationResponse` directly — never derived from request
headers, which is the canonical WebAuthn integration footgun.

## Static check

`ApprovalEvidenceSchema` from Phase 1 untouched: still
`method: z.literal("stub")`. Phase 3 will widen it to a discriminated
union with `webauthn`. The literal-not-string choice was made
specifically so this widening is an additive change, not a type
narrowing of every existing read site.

## Test results — `npm test`

6 / 6 green:

- 3 phase-1 approval tests (happy path, argument tampering, replay) — unchanged.
- 3 phase-2 enrollment tests:
  - **happy path** — `begin` → emulator response at the legitimate origin → `finish` → server stores credential → `GET /credentials` shows it.
  - **argument tampering** — challenge field inside `clientDataJSON` is flipped before submission → rejected with `-32001 / data.reason="verification_failed"` → credential count unchanged.
  - **wrong origin** — `clientDataJSON.origin` tampered to `http://evil.example.com` before submission → rejected with `-32001 / data.reason="verification_failed"`.

Server log line during the wrong-origin test confirms the exact failure path:

```
[enroll] verification threw: Unexpected registration response origin
"http://evil.example.com", expected "http://localhost:5173"
```

### Note on the wrong-origin test shape

`nid-webauthn-emulator` does its own browser-style origin / RP-ID check
and refuses to sign for foreign origins (it throws `Invalid rpId`
before producing any response). That's the *browser's* defense layer.
The threat we want to test is "malicious client bypasses the browser
check and ships an attestation claiming a different origin" — the
server's `expectedOrigin` check is the ground-truth defense at the
trust boundary. The test simulates that by getting a valid response at
the legitimate origin, then mutating `clientDataJSON.origin` to
`evil.example.com` before submitting. Server rejects, as it must.

## Hardware test outcomes

Run on a Mac Studio with `npm run dev` (server on 3030, Vite on 5173).
Two real enrollments performed, both reached `finish` and stored
cleanly. Captured live from `GET /credentials`:

```json
[
  {
    "credentialId": "4oIrCodNSiZA",
    "transports": ["hybrid", "internal"],
    "createdAt": "2026-05-01T17:59:43.539Z"
  },
  {
    "credentialId": "XXGG7vmPy8cL",
    "transports": ["internal"],
    "createdAt": "2026-05-01T18:02:14.488Z"
  }
]
```

| credentialId (truncated) | transports | how it was enrolled |
|---|---|---|
| `4oIrCodNSiZA` | `["hybrid", "internal"]` | Mac browser's passkey sheet → save to iCloud Keychain (Apple platform authenticator). The credential was subsequently synced to the iPhone via iCloud, which is why `transports` advertises both `hybrid` and `internal`. |
| `XXGG7vmPy8cL` | `["internal"]` | Chrome on Mac → same-device platform authenticator (Touch ID + Chrome's local passkey provider). |

Both flows reached `verifyRegistrationResponse` and were stored. One
credential is now cross-device-usable via iCloud Keychain sync; the
other is bound to this Mac only.

Worth being precise about what the `transports` array tells us: it
describes *what transports the credential can be used over going
forward*, not *what transport was used at enrollment*. Both
credentials in this test were created in same-device ceremonies on
the Mac — neither involved a QR code or Bluetooth pairing at
enrollment time. The one that advertises `["hybrid", "internal"]`
does so because the credential ended up on multiple devices via
iCloud sync, which is a use-time capability. A credential held by
any synced password manager (iCloud Keychain, Google Password
Manager, 1Password, etc.) will advertise `hybrid` because it can be
presented from a paired device, regardless of which device originally
created it.

### Multi-credential UI verification

After both enrollments, the UI rendered the credentials list with the
**most-recent** credential (Chrome / `XXGG7vmPy8cL`) marked with the
green `current` badge, and the older credential (iPhone /
`4oIrCodNSiZA`) below it with no badge. This matches the design
decision made before implementation: re-enrollment ADDS rather than
replaces, multiple credentials per user is the realistic shape (laptop
+ phone + hardware key), and the UI surfaces "which one is most
recent" without hiding the rest.

Status badge transitioned from red `not enrolled` to green
`enrolled (1 credential)` after the first enrollment, then to
`enrolled (2 credentials)` after the second. Re-attempting an
enrollment from the same Chrome platform authenticator after step 2
correctly tripped `excludeCredentials` (the OS passkey sheet refused
to offer the existing credential).

## Phase 1 regression check

Phase 2 changed the client UI structurally — added a new section above
the tool list and a separate enrollment log. Re-ran the unchanged
[scripts/e2e-step5.mjs](../scripts/e2e-step5.mjs) harness against the
new build:

- approve path → modal opens with `displayText`, Approve clicked, trade executes, server `/trades` grows by one
- cancel path → log shows `user declined`, server `/trades` unchanged
- escape path → native `<dialog>` close fires, log shows `user declined`, server `/trades` unchanged

All three behave identically to `phase-1-meta-migration`. The Phase 1
approval logic, modal, schema layout, and tool-call wire format are
byte-identical.

## Findings

### Finding 1 — `transports` must be treated as security-relevant in Phase 3

Phase 2 stores the `transports` array but does not differentiate or
enforce based on it. In Phase 3, this array becomes load-bearing:
which transports a credential advertises determines whether that
credential is eligible for which tools.

Concretely, the Phase 1 wrong-origin test demonstrated that a
malicious client can mutate any field in `clientDataJSON` that the
server doesn't pin against an authenticated source. The same mutability
applies to any field the server takes at face value. `transports` is
returned by the authenticator inside the attestation, so we *can*
verify it — but Phase 3 needs to actually do that, not casually trust
the field. Worth flagging now so it doesn't get treated as advisory
metadata when the assertion path lands.

### Finding 2 — Authenticator-class policy: ✅ resolved

Phase 2's two-credential test surface (one `hybrid`, one
`internal`-only) made the open question concrete: when the user
asserts with the same-device Chrome credential against `place_trade`,
should it succeed, or should the server demand the iPhone-via-hybrid
credential?

**Resolved during Phase 2 → Phase 3 transition.** The decision is
recorded in full in [DECISIONS.md](../docs/DECISIONS.md) under
*"Authenticator class policy: roaming required for high-sensitivity
tools."* Summary:

- High-sensitivity tools (the default for any tool flagged
  `verifiedApproval/required: "verified"`) require credentials with
  **cross-platform** transports. Same-device platform authenticators
  (`transports: ["internal"]` only) are not eligible by default.
- Spec field: `approvalAuthenticatorClass: "cross-platform" | "platform"`
  on the tool's `_meta.verifiedApproval`. Default: `"cross-platform"`.
  Tool authors must opt in deliberately to accept platform
  authenticators.
- Phase 3 enforces this on both sides: server filters
  `allowCredentials` during challenge issuance to exclude ineligible
  credentials, and rejects assertions from ineligible credentials at
  verify time with a structured `authenticator_class_mismatch` error.

The Phase 2 multi-credential setup is exactly the test surface Phase 3
needs: the iCloud-synced credential (`["hybrid", "internal"]`) should
be accepted for `place_trade`, and the Chrome-internal-only credential
should be rejected with `authenticator_class_mismatch`.

### Finding 3 — Enrollment ceremony and use-time transport are different properties

Synced passkeys (iCloud Keychain, Google Password Manager, 1Password,
etc.) blur the line between same-device and cross-device authenticators
because the credential exists in multiple places. The `transports`
array reflects use-time capability, not enrollment provenance.

This matters for Phase 3's authenticator-class enforcement. Rejecting
`transports: ["internal"]` correctly excludes credentials that exist
*only* on this Mac (and therefore offer no separation from a
compromised client). But accepting `transports: ["hybrid", "internal"]`
does **not** by itself prove the user enrolled from a separate device
— it only proves the credential is now usable from one. Use-time
separation is what the threat model actually cares about (a compromised
client can't produce a signature when the authenticator is on a
different device that performs its own user verification), so this is
the right property to enforce. The eventual SEP needs to acknowledge
this distinction explicitly: authenticator-class policy is a *use-time*
property, not an *enrollment-provenance* guarantee.

## What's intentionally not in Phase 2

- **No assertion / per-call signature verification.** Tool calls still
  use stub evidence. Phase 3 replaces that with a real WebAuthn
  signature over the action hash.
- **No persistent storage.** Credentials live in memory and are
  cleared on server restart, by design.
- **No multi-user model.** Single hardcoded `USER_HANDLE`; all
  credentials enrolled in Phase 2 are bound to it.
- **No authenticator-class policy enforcement** — the decision is
  made (Finding 2 above), the implementation lands in Phase 3.

## Bottom line

Six tests green. Both transport profiles (hybrid cross-device and
internal same-device) verified on real hardware. Multi-credential UI
behavior matches the design decision. Public-key bytes are not exposed
even in the debug endpoint. Phase 1 trade flow regression-clean. The
authenticator-class question moved from open to resolved with a
concrete spec field and an enforcement plan.

Phase 2 is done. Phase 3 builds the assertion path on top of this
enrollment foundation, with the authenticator-class policy as a
first-class design constraint rather than an afterthought.
