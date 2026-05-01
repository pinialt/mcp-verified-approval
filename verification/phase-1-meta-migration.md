# Phase 1 — `_meta` migration verification

Reference commit: `991fb32` (`phase-1-meta-migration: move approvalEvidence into params._meta.verifiedApproval`)
Tag: `phase-1-meta-migration`

This report documents the post-migration review. The change moved the
`approvalEvidence` field on `tools/call` from a top-level `params.approvalEvidence`
sibling (Phase 1) into `params._meta.verifiedApproval`, so both halves of the
extension (the tool-listing annotation and the call-time evidence) live in
`_meta` — the spec-sanctioned extension namespace.

Four properties were checked.

## 1. Wire format on `tools/call`

Captured at runtime by intercepting `globalThis.fetch` in a Node MCP client and inspecting the JSON-RPC body of the outgoing `tools/call`:

```json
{
  "method": "tools/call",
  "params": {
    "name": "place_trade",
    "arguments": {
      "symbol": "AAPL",
      "side": "buy",
      "quantity": 100,
      "limit": 180
    },
    "_meta": {
      "verifiedApproval": {
        "method": "stub",
        "challengeId": "76bba84d-73ea-4c0c-843b-962823c427e8",
        "userConfirmed": true
      }
    }
  },
  "jsonrpc": "2.0",
  "id": 2
}
```

No top-level `approvalEvidence` sibling. The evidence rides at `params._meta.verifiedApproval` exactly as briefed. Verdict: correct.

## 2. SDK-defined `_meta` keys still round-trip

This was the specific worry from the migration brief — that declaring `verifiedApproval` inside `_meta` via a custom extension schema would accidentally narrow the type and drop the SDK's existing namespaced keys (`progressToken`, `io.modelcontextprotocol/related-task`).

Procedure: temporarily added a `console.log(_meta)` in the server's `tools/call` handler, then sent a request with all three keys present in `_meta`. Server output:

```
[verify] parsed _meta keys: ["verifiedApproval","progressToken","io.modelcontextprotocol/related-task"]
[verify] parsed _meta value: {
  "verifiedApproval": { "method": "stub", "challengeId": "04c9a32d-...", "userConfirmed": true },
  "progressToken": "abc",
  "io.modelcontextprotocol/related-task": { "taskId": "task-xyz" }
}
[trade] 2026-05-01T17:07:18.478Z buy 7 AAPL @ 180 -> 0574e25d-...
```

All three keys survived parsing. The trade succeeded (proving the evidence read site works against the same parsed object). Temp log reverted via `git restore`; diff against the committed state was empty.

This works because the extension schema is:

```ts
const CallToolRequestSchema = z.object({
  method: z.literal("tools/call"),
  params: z.object({
    name: z.string(),
    arguments: z.record(z.string(), z.unknown()).optional(),
    _meta: z
      .object({ verifiedApproval: ApprovalEvidenceSchema.optional() })
      .passthrough()      // <-- this is what preserves SDK keys
      .optional(),
  }),
});
```

`.passthrough()` is the zod operator that mirrors the SDK's own `z.core.$loose` on the request-side `_meta`. Verdict: composition is correct.

## 3. `ApprovalEvidenceSchema` uses `z.literal("stub")` for `method`

[server/src/index.ts:91-95](../server/src/index.ts#L91-L95):

```ts
const ApprovalEvidenceSchema = z.object({
  method: z.literal("stub"),
  challengeId: z.string(),
  userConfirmed: z.literal(true),
});
```

Verdict: correct. Phase 3 will turn this into:

```ts
const ApprovalEvidenceSchema = z.discriminatedUnion("method", [
  z.object({ method: z.literal("stub"), challengeId: z.string(), userConfirmed: z.literal(true) }),
  z.object({ method: z.literal("webauthn"), challengeId: z.string(), credentialId: z.string(), /* ... */ }),
]);
```

Starting from a literal makes that an additive change. Starting from `z.string()` would have been a type widening that broke every existing read site.

## 4. Tests and browser flow unchanged

`npm test` post-migration: 3 of 3 green (happy path, argument tampering, replay). Assertions on `data.reason` strings are byte-identical to the pre-migration suite — only the `callTool` helper changed, to put evidence in `_meta.verifiedApproval`.

Browser end-to-end via [scripts/e2e-step5.mjs](../scripts/e2e-step5.mjs) (CDP-driven through headless Chrome): approve / cancel-button / escape paths all behave identically to `phase-1-complete`. The harness itself was unchanged — it drives clicks on the live UI rather than constructing payloads — so the migrated client is what produced the on-the-wire request.

## Summary

Migration is clean. The `_meta` extension namespace now hosts both halves of the verified-approval mechanism:

| Direction | Location |
|-----------|----------|
| Server → client (annotation that a tool needs approval) | `tool._meta["verifiedApproval/required"] = "verified"` |
| Client → server (evidence that a user approved) | `params._meta.verifiedApproval = { method, challengeId, userConfirmed }` |

The eventual SEP can describe the entire mechanism as `_meta`-resident, mirroring the SDK's own pattern for `progressToken` and `io.modelcontextprotocol/related-task` — no SDK modifications required.
