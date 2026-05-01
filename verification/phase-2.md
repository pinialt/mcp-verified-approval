# Phase 2 verification

Reference commit: `02665bb` (`phase-2-step-d: client enrollment UI`)
Tag: `phase-2-complete`

This report documents the post-implementation review of Phase 2 — real
WebAuthn enrollment with `@simplewebauthn/server` v13.3.0. Tool calls
remain unchanged (stub evidence); enrollment and assertion are
independently fiddly and Phase 3 builds the assertion side on top of
this enrollment foundation.

## What was added

- `approval/enroll/begin` and `approval/enroll/finish` MCP request handlers
  on the server. Pending challenges keyed by `userHandle` with a 5-minute
  TTL and the existing reaper.
- `Map<credentialId, CredentialRecord>` storing `{ credentialId, publicKey,
  counter, transports, userHandle, createdAt }`. Cleared on server
  restart, like trades.
- `GET /credentials` debug endpoint returning `{ credentialId, transports,
  userHandle, createdAt }` — public-key bytes are intentionally not
  exposed even in dev.
- Client UI: an Authenticator section above the tool list with a status
  badge, an "Enroll for approvals" button, an enrolled-credentials list
  (most-recent gets a `current` badge), and a separate enrollment log.
- Three vitest cases driven by `nid-webauthn-emulator` (Nikkei) as a
  software authenticator. No mocks of the verification path itself —
  the emulator produces real CTAP responses that flow through
  `verifyRegistrationResponse`.

## Static check

`ApprovalEvidenceSchema` from Phase 1 untouched: still
`method: z.literal("stub")`. Phase 3 will widen it to a discriminated
union with `webauthn`. RP_ID, EXPECTED_ORIGIN, and USER_HANDLE are
shared constants — never derived from request headers, which is the
known WebAuthn footgun.

## Test results

`npm test` runs 6 / 6 green:

- 3 phase-1 approval tests (happy / tampering / replay) — unchanged.
- 3 phase-2 enrollment tests:
  - **happy path** — `begin` → emulator response at the legitimate origin → `finish` → server stores the credential → `GET /credentials` shows it.
  - **argument tampering** — challenge field inside `clientDataJSON` is flipped before submission → rejected with `-32001 / data.reason="verification_failed"` → credential count unchanged.
  - **wrong origin** — `clientDataJSON.origin` tampered to `"http://evil.example.com"` before submission → rejected with `-32001 / data.reason="verification_failed"`.

Server log line during the wrong-origin test confirms the exact failure path:

```
[enroll] verification threw: Unexpected registration response origin
"http://evil.example.com", expected "http://localhost:5173"
```

### Note on the wrong-origin test shape

`nid-webauthn-emulator` does its own browser-style origin / RP-ID check
and refuses to sign for foreign origins (it throws `Invalid rpId` before
producing any response). That's the *browser's* defense layer. The
threat model we want to test is "malicious client bypasses the browser
check and ships an attestation claiming a different origin" — the
server's `expectedOrigin` check is the ground-truth defense at the
trust boundary. The test simulates that by getting a valid response at
the legitimate origin, then mutating `clientDataJSON.origin` to
`evil.example.com` before submitting. Server rejects, as it must.

## Real-hardware verification

Run on a Mac Studio with `npm run dev` (server on 3030, Vite on 5173).
Two enrollments performed in Safari/Chrome:

| credentialId (truncated) | createdAt | transports | flow |
|---|---|---|---|
| `4oIrCodNSiZA` | 2026-05-01T17:59:43.539Z | `["hybrid", "internal"]` | iPhone-as-roaming via Mac → QR → iPhone Camera → Face ID, iCloud Keychain sync |
| `XXGG7vmPy8cL` | 2026-05-01T18:02:14.488Z | `["internal"]` | same-device platform authenticator (Chrome) |

Captured live from `GET /credentials`:

```json
[
  { "credentialId": "4oIrCodNSiZA", "transports": ["hybrid", "internal"], "createdAt": "2026-05-01T17:59:43.539Z" },
  { "credentialId": "XXGG7vmPy8cL", "transports": ["internal"],            "createdAt": "2026-05-01T18:02:14.488Z" }
]
```

Both flows reached `finish` and stored a credential. Re-enrollment was
additive (multi-credential design decision); UI rendered the
most-recent (Chrome) with the `current` badge and the older
(hybrid/iPhone) below it.

## Trade-flow regression check

Phase 2 changed the client UI structurally — added a section above the
tool list and a separate enrollment log. Before committing, re-ran the
unchanged `scripts/e2e-step5.mjs` harness against the new build:

- approve path → modal opens with displayText, Approve clicked, trade
  executes, server `/trades` grows by one
- cancel path → log shows `user declined`, server `/trades` unchanged
- escape path → native `<dialog>` close fires, log shows
  `user declined`, server `/trades` unchanged

All three behave identically to `phase-1-meta-migration`. Stub
evidence path is byte-identical; Phase 1 approval logic is untouched.

## What's intentionally not yet here

- **No assertion / per-call signature verification.** Tool calls still
  use stub evidence. Linking enrolled credentials to tool-call
  approval is Phase 3.
- **No persistent storage.** Credentials live in memory and are cleared
  on server restart, by design.
- **No multi-user model.** Single hardcoded `USER_HANDLE`; all
  credentials enrolled in Phase 2 are bound to it.
- **No authenticator-class policy.** PROJECT.md notes that high-sensitivity
  tools should require a roaming authenticator (e.g. iPhone via hybrid)
  rather than same-device platform — same-device may be acceptable for
  medium-sensitivity. Phase 2 stores `transports` but doesn't
  differentiate or enforce. Phase 3 will need a policy hook reading
  `transports` to decide which credentials qualify for which tools.

## Carry-forward to Phase 3

In addition to the two items already deferred from Phase 1
(`invalid_challenge` sub-reasons; centralized `_meta` lookup), Phase 3
should:

- Decide the authenticator-class policy: gate `place_trade` (the
  high-sensitivity demo) on a credential whose `transports` includes
  `hybrid` (or another roaming class), or accept any enrolled
  credential. Either is defensible for the demo; the *spec* in Phase 4
  needs to take a position.
- Treat the `transports` field as security-relevant, not advisory.
  `nid-webauthn-emulator` proved that a malicious client can mutate
  `clientDataJSON.origin` — the same is true of any field the server
  doesn't pin against an authenticated source. `transports` comes from
  the authenticator's attestation, which we have, so this is solvable;
  worth flagging now so it doesn't get treated as casual metadata in
  Phase 3.

## Bottom line

Six tests green, hybrid + platform enrollment paths both working on
real hardware, multi-credential additive behavior verified, public-key
bytes not exposed in the debug endpoint, Phase 1 trade flow
regression-clean. Phase 2 is done.
