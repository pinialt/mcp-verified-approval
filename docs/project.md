# MCP Verified Approval — Project Context

## What this project is

A reference implementation for a proposed MCP (Model Context Protocol) extension that adds cryptographically verified human approval for sensitive tool calls. The eventual deliverable is a SEP (Specification Enhancement Proposal) submitted to the MCP spec repo, backed by a working prototype that demonstrates the security properties.

## The problem

MCP today provides advisory tool annotations (`destructiveHint`, `readOnlyHint`, etc.) and expects clients to surface a confirmation UI for sensitive tools. In practice this collapses to a button click — which an agent can effectively trigger itself in any context where the same process drives both the LLM loop and the approval UI (auto-approve modes, headless agents, prompt-injected approval flows, sycophantic confirmation). For tools that move money, deploy infrastructure, or delete data, "the client promises to ask" is not a strong enough enforcement model.

## The proposal

Servers mark sensitive tools by setting `_meta["io.modelcontextprotocol/verified-approval"] = { required: "verified" }` on the tool listing (with an optional `authenticatorClass` field). Before invoking such a tool, clients must:
1. Request a per-call challenge from the server (`approval/challenge/create`).
2. Obtain a cryptographic signature from a separate authenticator (passkey on a phone, hardware key) bound to a hash of `(toolName, canonicalArguments, serverId)`.
3. Submit the evidence with the tool call (`tools/call` with `params._meta["io.modelcontextprotocol/verified-approval"]`).

The server independently verifies the signature, the freshness of the challenge, and that the action hash matches the actual call. The enforcement point moves from "the client promises to ask" to "the server refuses to execute without proof."

The novelty over standard WebAuthn is the argument-binding: the signature certifies not just "a human is present" but "a human approved exactly this call with exactly these arguments."

## Scope decisions

- **Method-agnostic envelope, WebAuthn as first profile.** The protocol defines an evidence shape with a `method` discriminator. Phase 1–4 implement and ship `webauthn` as the only conformant method; future methods can be added without spec churn.
- **Authenticator-class policy as a capability filter.** High-sensitivity tools default to `authenticatorClass: "cross-platform"`, which excludes credentials whose transports advertise only `["internal"]` (same-device-only) at enrollment and at challenge issuance. This is a capability filter at enrollment time, not a guarantee about which device the user actually signs on. Synced credentials may be presented locally and still satisfy the filter; mitigating that requires platform-side changes documented as future work. Tools may opt into `authenticatorClass: "platform"` to accept any enrolled credential. See DECISIONS.md "Authenticator class policy" for what this delivers and what it does not.
- **`_meta` placement, not `annotations`.** Both the tool-side requirement flag and the request-side evidence live in `_meta`. Reasoning: `annotations` is defined by the spec as advisory; our field is normative. `_meta` is the spec-sanctioned extension namespace and matches how the SDK itself layers `progressToken` and `io.modelcontextprotocol/related-task`.
- **One canonicalization algorithm: RFC 8785 (JCS).** Via `canonicalize@3.0.0` by Erdtman (RFC author).
- **Single dangerous tool in the demo: `place_trade`.** Vivid for demos, no external integrations needed. The whole point is the approval ceremony, not the trading logic.

## What I'm explicitly not solving

- Agent identity and capability scoping — that's SMCP's territory (discussion #689). Verified approval composes with SMCP rather than replacing it.
- Server-side policy enforcement framework — that's Sebastian Mart's draft (`sebastianmart-sketch/mcp-server-side-policy-enforcement`). My work fits as a profile under his framework.
- Identity verification in the "this specific human" sense. The proposal proves "*an* enrolled human approved," not "*this specific* human." Identity sits in the existing OAuth layer.
- Recovery, headless contexts, batched approval, multi-party signing. Acknowledged as known limitations; v2 territory.

## Architecture (locked from Phase 0)

- **Stack:** TypeScript monorepo, npm workspaces. Library: `mcp-verified-approval/` (with `shared`, `server`, `client` subpath exports). Demo app: `shared/`, `server/`, `client/` workspaces consuming the library.
- **MCP SDK:** `@modelcontextprotocol/sdk@1.29.0`.
- **Transport:** `StreamableHTTPServerTransport` (server) / `StreamableHTTPClientTransport` (client). Stateful sessions via `Mcp-Session-Id`.
- **Server:** Node, port 3030 (3000 was in use locally during Phase 0). Exposes `place_trade` plus a debug `GET /trades` endpoint. In-memory state only.
- **Client:** Vite + vanilla TypeScript, no framework. Port 5173. Real `<dialog>` modal for approval prompts.
- **CORS:** Pinned to `http://localhost:5173` with allowed methods `GET, POST, DELETE, OPTIONS` and headers including `mcp-session-id` and `mcp-protocol-version`.
- **Tests:** vitest. Real server on a random port, real client. No mocks for protocol behavior.

## Repository structure

```
mcp-verified-approval/   Reference library (shared / server / client subpath exports).
shared/                  Types and helpers used by both demo workspaces.
server/                  Demo MCP server consuming the library.
server/test/             vitest tests against a real server instance.
client/                  Browser-based demo MCP client.
scripts/                 e2e harnesses driven via CDP.
verification/            Per-phase verification reports (evidence for the eventual SEP).
sep-draft/               SEP markdown draft.
docs/DECISIONS.md        Running log of design decisions with rationale.
docs/project.md          This file.
docs/roadmap.md          Phases, status, pending tasks.
```

## Tagged anchors

- `phase-0-complete` — scaffolding, MCP loop, no approval logic.
- `phase-1-complete` — protocol skeleton with stub evidence at `params.approvalEvidence` (sibling).
- `phase-1-meta-migration` — evidence relocated to `params._meta.verifiedApproval`. Phase 2 builds on this.

## Related work in the MCP ecosystem

- **SMCP / SEAL Protocol** (discussion #689, by Theaxiom / 100monkeys.ai). Adds Ed25519 signatures over MCP messages for *agent identity and capability scoping*. Different layer — no human in the loop. Composes with this proposal rather than competing.
- **Server-Side Policy Enforcement SEP** (Sebastian Mart's draft repo). Defines the contract that the server is the final Policy Enforcement Point with server-trusted evidence. Explicitly excludes "a universal mechanism for proving whether the actor is human" — the gap this proposal fills. Verified approval fits as one profile under his framework.
- **MCP existing primitives.** Tool annotations are advisory only. Elicitation is a software prompt the agent can drive. OAuth handles session-level authorization, not per-call human approval. None of these provide the security property this proposal targets.

## Eventual SEP submission shape

- One markdown file in `modelcontextprotocol/modelcontextprotocol/seps/` opened as a PR.
- Reference implementation lives in this repo, linked from the SEP.
- Eight required sections: Preamble, Abstract, Motivation, Specification, Rationale, Backward Compatibility, Reference Implementation, Security Implications.
- Requires a Sponsor (Core Maintainer or Maintainer). Sebastian Mart is *not* a sponsor candidate — peer collaborator only. Sponsor identification is part of pre-Phase-4 community homework.
- 2-week review cadence at Core Maintainer meetings once formally `in-review`. Plan for 4–6 weeks of formal review minimum.

## Process discipline patterns

Patterns that have surfaced repeatedly during the project, worth writing down:

**Spec-as-bug-finder.** When the SEP draft tightens a normative claim (new MUST, stricter check, modified semantics), cross-check the library and reference implementation immediately — don't carry the spec forward while the implementation lags. Twice during this project, drafting normative text surfaced gaps the implementation wasn't yet enforcing: once during §4 drafting (enrollment defenses, error-enum coverage), and once after the §4.6 serverId uniqueness MUST landed (the demo's hardcoded `SERVER_ID = "phase-3-dev-server"` constant became non-conformant). Pattern: spec change → cross-check pass → fix or document any gaps before moving on.

**External review processing.** Each round of external review (Perplexity x3, Gemini x1) produced a mix of "take it" and "push back on it" items. The pattern that worked: respond to every suggestion explicitly, taking the substantive ones and explaining the reasoning when pushing back. Suggestions to soften over-assertive prose ("authoritative description" → "human-readable surface that pairs with cryptographic binding") were almost always worth taking. Suggestions to add new fields or expand scope ("add a security-level annotation") were almost always worth pushing back on if the existing surface already addressed the underlying concern. The discipline is per-suggestion judgment, not per-review acceptance.

**One commit per coherent change.** Single-purpose commits (e.g., `sep-draft: §4.6 serverId uniqueness MUST, §8.3.1 transport-observability gap diagnosis, §8.4 non-browser clients and transport gap framing (Gemini review)`) make the SEP's revision history self-explanatory and make it easy to revert a specific revision if a reviewer pushes back. Avoiding "misc cleanup" commits keeps each step in the chain reviewable on its own terms.