# Phase 1 verification

Reference commit: `77b7208` (`phase-1-step-5: end-to-end browser harness for the three approval paths`)
Tag: `phase-1-complete`

This report documents the post-implementation review of Phase 1 — the
verified-approval protocol skeleton with stub evidence. Five properties were
checked against the running system; two of them produced carry-forward items
for Phase 2.

## 1. Argument-tampering test is honest

[server/test/approval.test.ts:88-100](../server/test/approval.test.ts#L88-L100):

- Creates a challenge with `{ symbol: "AAPL", side: "buy", quantity: 100, limit: 180 }`.
- Calls `tools/call` with `{ ..., quantity: 1000 }` and the original `challengeId`.
- Asserts via `expectApprovalError(err, "argument_hash_mismatch")` (helper at lines 61-66) which checks `e.code === -32001` AND `e.data.reason === "argument_hash_mismatch"` — not just any error.

The server check order at [server/src/index.ts:202-213](../server/src/index.ts#L202-L213) puts `invalid_challenge` (existence / consumed / expired / wrong tool name) **before** the hash comparison. The only way the test reaches `argument_hash_mismatch` is if the challenge is alive at call time AND the canonical hash differs. TTL is 60 s, the test runs in ~50 ms — no expiry path is reachable.

Verdict: honest.

## 2. Replay test is honest under current TTL — quality caveat for Phase 2

[server/test/approval.test.ts:102-118](../server/test/approval.test.ts#L102-L118):

- Creates a challenge, calls successfully, then calls again with the same `challengeId`.
- Asserts `data.reason === "invalid_challenge"`.

Caveat: at [server/src/index.ts:202](../server/src/index.ts#L202), the **same** reason `"invalid_challenge"` is emitted for four distinct conditions — missing entry, consumed, expired, wrong tool name. The test cannot tell them apart from `data.reason` alone. Under normal TTL (60 s vs ~50 ms test runtime) only the consumed path can fire. But if TTL were ever shortened, the test would silently pass for the expired reason instead of consumption.

**Phase 2 carry-forward**: split `invalid_challenge` into specific reasons (`consumed`, `expired`, `unknown`, `wrong_tool`) so the replay test asserts on the precise consumption invariant.

## 3. Atomicity comment exists, with a small precision nit

[server/src/index.ts:215-218](../server/src/index.ts#L215-L218):

```ts
// Atomic consume: Node is single-threaded so this check-and-set cannot be
// interrupted within one event-loop tick. Phase 4 may extract this into a
// multi-process server — at that point this needs a real CAS (DB row lock,
// Redis SETNX, etc.) so two workers can't both consume the same challenge.
```

What's right: tells a Phase 4 maintainer to swap to a real CAS when extracting to multi-process.

What's slightly imprecise: there's an `await computeActionHash(...)` at [line 207](../server/src/index.ts#L207) between the initial validity check at [line 202](../server/src/index.ts#L202) and the consume check at [line 219](../server/src/index.ts#L219). Two concurrent calls *can* race past the first check. What actually saves us is the **late re-read** at line 219 (`if (stored.consumed)`) — by the time the loser resumes, the winner has set `consumed = true`. The current comment phrase "within one event-loop tick" reads like the whole handler is one tick, when it's actually two ticks bridged by a re-check.

Suggested wording (not changed in this phase):

> The check-and-set on lines 219-222 happens synchronously in one event-loop tick — those four lines cannot interleave. The earlier validity check (line 202) can race because of the `await` above, but the late re-read here catches that. In a multi-process server, replace with a real CAS.

Verdict: comment is present, readable, and correct in spirit. Sharpening it can wait for Phase 4.

## 4. Display-text path is correct

[client/src/main.ts:75](../client/src/main.ts#L75):

```ts
dialogTextEl.textContent = challenge.displayText;
```

The string shown to the user in the modal is `challenge.displayText` exactly — the value the server returned in the challenge response. Nothing is reconstructed from the form arguments. The metadata line below it (truncated `challengeId`, `actionHash`, `expiresAt`) is also straight from the server response.

`textContent` (not `innerHTML`) closes the XSS surface for any future server that returns adversarial `displayText`. The eventual security argument that "what the user saw is what the server committed to" holds.

## 5. Tool without `_meta` regression — passes via temp edit, with an architecture nit

Procedure: temporarily added a second tool `ping` to `tools/list` with no `_meta`, plus a `name === "ping"` branch in the call handler that bypasses approval. Real client confirmed:

```
=== tools/list ===
- place_trade  _meta={"verifiedApproval/required":"verified"}
- ping  _meta=undefined

=== call ping (no evidence) ===
{"content":[{"type":"text","text":"pong"}]}

=== call place_trade (no evidence) — should still reject ===
{"error":{"code":-32001,"data":{"reason":"missing_evidence"},...}}
```

`git restore server/src/index.ts` then `npm test` → 3/3 green. Revert clean.

**Phase 2 carry-forward**: the call handler at [server/src/index.ts:191-194](../server/src/index.ts#L191-L194) gates approval by **hardcoded tool name** (`if (name !== TOOL_NAME) throw …`), not by reading the registered tool's `_meta`. For Phase 1 (one tool) this is fine — the bug class the brief warns about ("approval logic accidentally applies to all tools") is structurally absent because approval lives **inside** the `place_trade` branch. But when a second annotated tool arrives in Phase 2, a developer adding it has to remember to wire the approval check into the new branch; there's no central registry consulting `_meta`. Refactor to `Map<name, { _meta, handler }>` and gate approval by `_meta?.[VERIFIED_APPROVAL_META_KEY] === VERIFIED_APPROVAL_VERIFIED` when that day comes. Don't pre-emptively do this in Phase 1 — it's a single-tool YAGNI.

## Summary

All five properties hold. Two carry-forwards for Phase 2:

1. Split `invalid_challenge` reasons so the replay test asserts on `consumed` specifically.
2. Move approval enforcement from per-tool branches to a central `_meta` lookup once a second annotated tool exists.
