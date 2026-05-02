# Phase 4 mitigation 1 — investigation report (PARTIAL)

Branch: `phase-4-mitigation-1-investigation`
Commit: `f680443` — *phase-4-mitigation-1: hints: ["hybrid"] in assertion options*
Status: **NOT COMPLETE.** Code change landed and unit tests green. Hardware
observation portion of the brief was not executed — see "What was not run"
below. The branch is unmerged.

## What this investigation is for

Phase 3 verification's Finding 4 documented that the transport-class
filter is a *capability* check, not a *use-time guarantee*: an
iCloud-synced credential whose transports advertise `["hybrid",
"internal"]` is locally usable on the Mac via Touch ID, so the OS
picker prefers the local biometric path even though hybrid is
available. The display-tampering threat-model claim that motivated
the cross-platform-required policy is therefore not delivered for
synced credentials.

The question for this task: **does adding a WebAuthn Level 3 hint
(`hints: ["hybrid"]`) to the assertion request options cause Apple's
authenticator picker to skip the local Touch-ID path and prefer the
cross-device path?** The answer determines whether the SEP can keep
the display-surface-separation claim or must narrow it to
"argument-binding + freshness + single-use."

## Brief deviation: which field to use

The original task brief said to set
`authenticatorSelection: { authenticatorAttachment: "cross-platform" }`
on `PublicKeyCredentialRequestOptionsJSON`. Inspection of the WebAuthn
types showed that field is **registration-only**:

- `PublicKeyCredentialCreationOptionsJSON` HAS `authenticatorSelection?:
  AuthenticatorSelectionCriteria` — see
  [@simplewebauthn/server/esm/types/index.d.ts:20-32](../node_modules/@simplewebauthn/server/esm/types/index.d.ts#L20-L32).
- `PublicKeyCredentialRequestOptionsJSON` does **not**:

  ```ts
  export interface PublicKeyCredentialRequestOptionsJSON {
      challenge: Base64URLString;
      timeout?: number;
      rpId?: string;
      allowCredentials?: PublicKeyCredentialDescriptorJSON[];
      userVerification?: UserVerificationRequirement;
      hints?: PublicKeyCredentialHint[];
      extensions?: AuthenticationExtensionsClientInputs;
  }
  ```
  ([index.d.ts:37-45](../node_modules/@simplewebauthn/server/esm/types/index.d.ts#L37-L45))

The W3C-spec analogue on the assertion side is `hints?:
PublicKeyCredentialHint[]` with values `'hybrid' | 'security-key' |
'client-device'`. After confirming with the user, the change uses
`hints: ["hybrid"]` — the spec-correct L3 mechanism for nudging the
picker toward the cross-device transport on the Get ceremony.

## Environment

| | |
|---|---|
| macOS | 26.4.1 (build 25E253) |
| Safari | 26.4 (21624.1.16.11.4) |
| Chrome | 147.0.7727.138 |
| WebKit (system framework) | 21624 |

**WebAuthn Level 3 `hints` browser support, as of test date
(2026-05-01):**

- WebKit shipped `PublicKeyCredentialRequestOptions.hints` in the
  WebKit 17.4 timeframe. Safari 26.4 (build 21624.1.16.11.4) is
  several major versions past 17.4 and is expected to know the
  field. Whether it actually steers the macOS system picker is the
  experimental question.
- Chrome 147 is well past Chrome 122, where L3 `hints` first shipped
  with full implementation. Chrome on macOS uses the same Apple system
  picker for platform credentials, so Chrome behaviour with hints
  triangulates "is the browser sending the hint" vs "is the system
  picker honoring it."

**Note on browser-version load-bearing.** If a hardware test in Safari
shows the picker behaviour identical to control, the finding is
ambiguous between (a) Safari silently dropping the unrecognized field
and (b) Apple's system picker ignoring the hint. Running the same
scenario in Chrome 147 disambiguates these — Chrome will definitely
forward the field to the OS picker.

## The code change

One commit (`f680443`), four files, +13 lines:

```diff
diff --git a/server/src/index.ts b/server/src/index.ts
@@ -322,6 +322,12 @@ async function handleChallengeCreate(
     })),
     userVerification: "required",
     timeout: ASSERT_TIMEOUT_MS,
+    // Phase 4 mitigation 1 (investigation only): WebAuthn L3 hint to nudge
+    // the OS picker toward the cross-device path for synced credentials
+    // that advertise both `hybrid` and `internal`. Hints are advisory; the
+    // platform may ignore them. Outcome of hardware testing decides whether
+    // this stays.
+    hints: ["hybrid"],
   };
```

Plus the type-side widening so the field is type-checked rather than
cast through:

```diff
diff --git a/shared/src/index.ts b/shared/src/index.ts
@@ -1,4 +1,8 @@
 import canonicalize from "canonicalize";
+// Re-exported so server and client agree on the union without duplicating
+// the literal values. WebAuthn L3 hint set: spec-defined, advisory.
+export type { PublicKeyCredentialHint } from "@simplewebauthn/browser";
+import type { PublicKeyCredentialHint } from "@simplewebauthn/browser";

@@ export type PublicKeyCredentialRequestOptionsJSONShape = {
   userVerification?: "required" | "preferred" | "discouraged";
   timeout?: number;
+  hints?: PublicKeyCredentialHint[];
   extensions?: Record<string, unknown>;
 };
```

Plus `@simplewebauthn/browser` declared as a `dependencies` entry of
`shared/package.json` (the hoisted `node_modules` already had it via
the client). No runtime dependency change — it's a `import type` at
both the use site and the re-export.

## Test suite

`npm test` — 11/11 green on this branch:

- 3 phase-1 protocol-shape tests (`server/test/approval.test.ts`).
- 3 phase-2 enrollment tests (`server/test/enrollment.test.ts`).
- 5 phase-3 assertion tests (`server/test/assertion.test.ts`).

The unit tests do not assert on `hints` because the emulator
(`nid-webauthn-emulator`) doesn't model picker selection — picker
behaviour is, by definition, a hardware-level concern. The unit tests
confirm the wire shape still serializes, the existing schema still
validates, and the assertion verification path is unchanged.

## Hardware setup constraint

Current macOS / Safari (versions above) does not offer a "save on this
device only" option during passkey enrollment in Safari — the only
save destination Safari surfaces is iCloud Keychain. The Phase 3
hardware run captured a `["internal"]`-only credential because the
Mac password app at that time did surface a "this device only"
option; current macOS/Safari does not.

Chrome on the same Mac does offer a "save in Chrome" option in
addition to iCloud Keychain. A Chrome-saved passkey lives in Chrome's
own credential store and advertises `["internal"]` only — useful for
re-creating the Phase 3 dual-credential setup but NOT useful for the
hint experiment, since the hint is supposed to steer toward `hybrid`
and a Chrome-internal credential has no `hybrid` capability for the
hint to surface.

This constraint is actually convenient: the hint experiment only
needs a single iCloud-Keychain credential (transports
`["hybrid","internal"]`) — that is the credential class for which the
question "does the OS picker prefer hybrid or local?" is meaningful.
A single-credential setup is a cleaner A/B than the Phase 3
dual-credential setup because the picker only has to decide between
transports, not also between credentials.

## Hardware observations

Hardware: same Mac as Phase 3 hardware run. **Touch ID is not
available on this Mac** — the local biometric path the macOS picker
falls back to is the macOS login password. This does not invalidate
the test. The threat-model question is "does the gesture happen on a
display surface outside the (hypothetical) compromised client's
control?" Whatever local-presentation path macOS chooses (Touch ID,
password, Apple Watch) lands on the same Mac display the client
controls. The hint experiment is asking whether the OS picker can be
nudged AWAY from any of those local paths and toward the cross-device
QR/iPhone path.

### Scenario A — Safari, hint applied

Server: investigation branch, commit `f680443`, emits `hints:
["hybrid"]` in `approval/challenge/create`.

Single iCloud-Keychain credential enrolled (transports
`["hybrid","internal"]`).

After clicking Approve in the in-app modal, the macOS system Sign-In
sheet appeared with:
- Title: "Sign In"
- Body: 'Sign in to "localhost" with your passkey for "MCP Demo
  User"?'
- A row labeled "Passkey From" with the macOS Passwords-app icon on
  the right. **Row not clickable in Safari** — no dropdown, no hidden
  submenu.
- A passkey icon and the word "Passkey" centered.
- Cancel + Continue buttons.

**No "Use a phone or tablet" option, no QR affordance, no "Other
options" menu, no chevron, nothing that would surface the hybrid
transport.** The dialog had exactly two terminal actions: Cancel
(closes the sheet, no further options surfaced) or Continue (proceeds
with the local presentation of the iCloud-Keychain credential).

Continue → macOS asked for the user's login password (substituting
for Touch ID on Mac without Touch ID hardware). The user entered
their password on the same Mac display. The assertion completed.

Server log:
```
[approval] consumed f420421d-8229-45d8-8292-8b229bc4bca1 for place_trade; counter 0 -> 0
[trade] 2026-05-02T08:25:13.814Z buy 10 AAPL @ 150.5 -> faa7f17b-ca96-45ea-bd33-28677a9397ba
```

Counter `0 -> 0` is consistent with synced-passkey behaviour
(Phase 3 Finding 1).

Trade succeeded. Screenshot: `screenshots/A-safari.png`.

**Observation:** the `hints: ["hybrid"]` field, although emitted on
the wire by the server, did NOT cause Safari/macOS to offer the
hybrid (cross-device) transport. The picker went directly to local
presentation of the synced credential.

### Scenario B — Safari, try Touch ID

**Not directly applicable on this hardware** — Mac has no Touch ID.
The closest analogue is "complete the local presentation," which is
what Scenario A did via password. No separate gesture or path was
offered that we could explicitly select.

The threat-model property the test is examining (is the gesture on a
client-controlled display?) is unchanged by the absence of Touch ID:
password entry on the same Mac display has the same threat profile
as Touch ID on the same Mac.

### Scenario C — Safari, try iPhone via hybrid

**No path to invoke this from the Safari picker.** The Sign-In sheet
in Scenario A offered no "Use a phone or tablet" option, no
"different device" menu, and clicking Cancel does not surface
additional options in Safari (in contrast to Chrome, which does show
its own fallback menu after cancel — captured separately).

With one iCloud-Keychain credential enrolled and `hints: ["hybrid"]`
set, the cross-device transport was unreachable through Safari's
flow.

### Scenario A — Chrome, hint applied

Same investigation-branch server, same `hints: ["hybrid"]` on the
wire. iCloud Keychain credential is shared with Safari (iCloud
Keychain dedupes by (RP, userHandle); a fresh enrollment attempt in
Chrome reused the same credential rather than creating a new one).
`/credentials` continued to show one entry, transports
`["hybrid","internal"]`.

After clicking Approve in the in-app modal, **the macOS system
Sign-In sheet that appeared was visually identical to Safari's** —
same title, same body, same single "Passkey From Passwords" row,
same Cancel/Continue buttons. No hybrid option visible. Screenshot:
`screenshots/A-chrome.png` (system sheet) and
`screenshots/A-chrome-after-cancel.png` (Chrome fallback).

When Cancel was pressed on the system sheet, Chrome's own
browser-rendered fallback modal appeared:

- Title: "Use a saved passkey for localhost"
- Section "On this device": "MCP Demo User · Apple Passwords"
  (chevron, clickable — leads back to the Apple system sheet).
- Section "On other devices": "Use a phone or tablet" (chevron,
  clickable — would lead to the cross-device QR flow).
- Cancel button.

This Chrome-fallback modal IS browser-rendered (not the macOS system
sheet) and DOES surface the hybrid path under "On other devices".
**Whether the hint caused Chrome to surface this option is the
control-run question**: if Chrome's fallback shows "Use a phone or
tablet" without the hint as well, the hint is not what's exposing
it; if it doesn't, the hint is influencing Chrome's fallback content.

Critical observation for the threat model: the fallback modal
appears only AFTER the user clicks Cancel on the Apple system sheet.
The natural user flow (Approve → Continue) never reaches it. An
attacker controlling the client cannot force the user to click
Cancel; in the normal flow the user signs locally on the Apple
sheet, on the Mac display the (hypothetically compromised) client
controls.

### Control — Safari, no hint (PENDING)

To be captured against `main` (which does not emit the `hints` field).
Same single iCloud-Keychain credential setup. Single-cell question:
does the Safari picker behave identically to Scenario A (proving the
hint is moot) or differently (proving the hint suppressed/changed
something)?

### Chrome cross-check (PENDING)

Required to disambiguate "Safari is dropping the field" from "Apple's
system picker ignores the hint." Chrome 147 is well past the L3
implementation cutoff (Chrome 122) and forwards `hints` to the
platform. If Chrome on the same Mac shows the same single-option
sheet as Safari, the conclusion is firmly that Apple's system picker
is ignoring the hint; if Chrome shows additional options surfaced by
the hint, the conclusion is that WebKit is dropping the field.

User has noted that in Chrome, clicking Cancel on the system Sign-In
sheet brings up an additional Chrome-internal menu. That suggests
Chrome's flow has a richer fallback affordance than Safari's, but
whether it's hint-influenced needs both with-hint and without-hint
captures to compare.

## Preliminary reading — Safari with hint shows no hybrid path

Scenario A in Safari is unambiguous on the narrow question of "does
the hint cause the picker to surface a hybrid option": **it does
not**. With `hints: ["hybrid"]` set on the wire and a synced
credential locally available, Safari/macOS skipped any picker that
would have offered a cross-device path and went directly to local
presentation of the credential.

This is not yet the full answer — the control run determines whether
this is "Safari's picker ignores the hint" or "Safari's picker happens
to skip hybrid for locally-resolvable creds regardless." But on its
face, the result is consistent with Phase 3 Finding 4's prediction:
the cross-platform-class capability filter does not deliver use-time
display-surface separation for synced credentials.

## SEP framing — preliminary lean

The three-row decision table from the original task plan:

| Outcome | SEP implication |
|---|---|
| Picker skips local for the synced cred when `hints: ["hybrid"]` is set | Hint is a load-bearing mitigation. SEP can keep the display-surface-separation claim, contingent on RP setting hints. |
| Picker behaviour is identical to control | Hint is advisory and Apple ignores it. SEP must narrow the claim — argument-binding + freshness + single-use are load-bearing; display-surface separation is a capability check, not a use-time guarantee. |
| Picker partially respects | Mixed; SEP discusses the hint as one ingredient of layered defense, not a guarantee. |

Scenario A's outcome rules out row 1 for Safari at minimum. Rows 2
and 3 are still in play depending on the control. Final
recommendation pending control + Chrome captures.

## Status

- Branch `phase-4-mitigation-1-investigation` unmerged.
- Tests pass.
- DECISIONS.md unchanged, per the brief.
- Scenario A captured (Safari + hint).
- Control (Safari, no hint) and Chrome cross-checks pending hardware
  run.
