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

## What was not run — hardware observation portion

The brief calls for four hardware scenarios — A (default selection),
B (actively try Touch ID), C (actively try hybrid), and a control
(same as A but without the change). Each requires a human at the
keyboard to invoke the OS picker and physically press Touch ID or
scan a QR code with an iPhone for Face ID. These were **not run** in
this report.

The autonomous portion of this task can verify:
- the `hints: ["hybrid"]` field is present in the source emitted by
  `approval/challenge/create` (it is — see the diff);
- the type system accepts it without a cast (it does — `npx tsc -p
  server/tsconfig.json --noEmit` is clean);
- existing unit tests still pass (they do — 11/11).

The autonomous portion **cannot** verify:
- whether Safari forwards the field to the macOS system picker;
- whether the macOS system picker changes its default selection in
  response to the hint when an iCloud-synced credential is locally
  available;
- whether Touch ID is offered, hidden, demoted, or unchanged in the
  picker UI;
- whether the user can actively select Touch ID despite the hint
  (Scenario B);
- whether the user can actively select hybrid (Scenario C);
- the difference, if any, between Safari and Chrome on the same
  hardware with the same hint (the L3-vs-not disambiguation).

These are observations of UI behaviour outside the process that this
agent runs in. They are not skipped because of cost; they are skipped
because the agent has no eyes on the macOS system picker.

The remaining test plan is preserved in
[the prior turn of this conversation] and at the top of the
`screenshots/` directory: control first against a server with this
commit reverted, then A → B → C against the new server, optionally a
Chrome run of A if the Safari run is ambiguous. Per-scenario captures
needed: verbatim picker title, every option offered, default
highlight, gesture path actually taken, screenshot, server log
`credentialId` consumed, trade success.

## Cannot yet recommend an SEP framing

The brief's deliverable includes a clear statement of the form
*"Apple's picker [does / does not / partially does] respect
`authenticatorAttachment: cross-platform` for synced credentials in
this configuration"* and a recommendation for how the SEP should
treat the display-tampering claim. **Both are pending the hardware
run.** Three possible outcomes and their SEP implications:

| Outcome | SEP implication |
|---|---|
| Picker skips Touch ID for the synced cred when `hints: ["hybrid"]` is set | The hint is a load-bearing mitigation. SEP can keep the display-surface-separation claim, contingent on RP setting hints. |
| Picker behaviour is identical to control | The hint is advisory and Apple ignores it. SEP must narrow the claim — argument-binding + freshness + single-use are the load-bearing properties; display-surface separation is a capability check, not a use-time guarantee. |
| Picker partially respects (e.g. demotes Touch ID but still offers it) | Mixed. The SEP discusses the hint as one ingredient of a layered defense, not a guarantee. |

The choice between these branches is exactly the question the
hardware run is supposed to answer. Asserting any of them now would
be the kind of overclaim Phase 3 Finding 4 explicitly warns against.

## Status and next step for the human

- Branch `phase-4-mitigation-1-investigation` exists, has commit
  `f680443`, is unmerged.
- Tests pass.
- DECISIONS.md unchanged, per the brief.
- The hardware test plan is ready to execute as soon as a human is at
  the keyboard. When that happens, this report should be re-opened and
  the four scenario blocks filled in, plus the recommendation table
  above resolved into a single recommendation.

Until then, the SEP's framing of the display-tampering claim should be
treated as still-undecided. Phase 3 Finding 4 stands.
