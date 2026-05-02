# mcp-verified-approval

Reference implementation of the verified-approval extension for MCP — per-call, passkey-verified human approval for sensitive tool calls.

## What this is

MCP servers expose tools that LLM agents can call autonomously. For most tools, the existing advisory annotations (`destructiveHint`, `readOnlyHint`, etc.) and a client-rendered confirmation dialog suffice. For tools with high-stakes consequences — placing trades, deploying infrastructure, deleting data, transferring money — a confirmation dialog rendered by the same client that drives the agent is not enough: the same process can dismiss the dialog programmatically, comply with prompt-injected "click yes" instructions, or rely on auto-approve modes the user pre-authorized. The dialog is a UX affordance, not an enforcement primitive.

This repository is the reference implementation for a proposed MCP extension that closes that gap. Tools mark themselves as requiring approval via a `_meta` annotation; the server issues a challenge whose value is bound to a hash of the canonicalized arguments; the user authorizes the call through a WebAuthn assertion against an enrolled credential; the server independently verifies the signature and rejects argument substitution. The full specification, including normative requirements, threat model, and residual risks, lives in [`sep-draft/SEP-DRAFT.md`](./sep-draft/SEP-DRAFT.md).

The proposal is structurally additive: tools without the annotation behave exactly as they do today, and clients that do not implement the ceremony interact with all non-annotated tools normally.

## Status

The SEP is in draft and pre-submission review. The reference implementation is end-to-end working: 15 integration tests cover the §4.8 verification rules, §4.4.2 enrollment defenses, §4.10 error reasons, and the per-call ceremony. The WebAuthn assertion path has been hardware-tested on macOS Touch ID and iCloud Keychain synced passkeys via Mac → iPhone hybrid transport.

## Repository structure

```
mcp-verified-approval/   Reference library (shared / server / client subpath exports)
shared/                  Types shared by the demo workspaces
server/                  Demo MCP server consuming the library
server/test/             Integration test suite
client/                  Browser-based demo client
sep-draft/               SEP markdown draft
verification/            Per-phase verification reports
docs/                    Project context and design decisions
```

The library at `mcp-verified-approval/` is the canonical surface — server gate, client ceremony, shared protocol vocabulary, exported through three subpath imports. The demo workspaces (`server/`, `client/`, `shared/`) consume the library to exercise it end-to-end against a real MCP server and browser client. Verification reports under `verification/` document empirical findings cited in the SEP; `docs/` carries the running design-decision log.

## Quick start

Requires Node ≥ 20.

```sh
git clone git@github.com:<your-handle>/mcp-verified-approval.git
cd mcp-verified-approval
npm install
npm test
```

All 15 tests should pass. To run the demo with a browser:

```sh
npm run dev
```

This builds the library, starts the demo MCP server on port 3030, and starts the browser client on port 5173. Open `http://localhost:5173` in Safari or Chrome, enroll a passkey via the in-page button, and place a trade. The first run generates a per-deployment server identifier and persists it to `server/.serverid` (gitignored); subsequent runs reuse it.

## Reading order

For someone wanting to understand the work in depth:

- **The spec.** [`sep-draft/SEP-DRAFT.md`](./sep-draft/SEP-DRAFT.md) is the full specification. §3 frames the gap; §4 defines the wire format and verification rules; §8 documents the threat model and residual risks.
- **The canonical implementation.** [`mcp-verified-approval/src/server/index.ts`](./mcp-verified-approval/src/server/index.ts) implements `createApprovalGate`, the server-side enforcement primitive. The fourteen verification steps from SEP §4.8 map 1:1 to checks in `verifyApprovalForCall`.
- **The empirical findings.** [`verification/phase-4-mitigation-1.md`](./verification/phase-4-mitigation-1.md) documents the test that narrowed the authenticator-class claim from a use-time guarantee to a capability filter — the empirical observation that shaped §4.7 and §8.3.1. Other reports under `verification/` cover earlier phases.
- **The integration suite.** [`server/test/`](./server/test/) maps each test to a normative requirement: argument-binding, replay rejection, expired-challenge handling, authenticator-class enforcement, signature-counter regression, enrollment defenses, error-reason discrimination, and capability declaration.

## Hardware coverage

The WebAuthn assertion path has been hardware-tested on macOS Touch ID via Chrome (transports advertise `["internal"]`) and iCloud Keychain synced passkeys with Mac → iPhone hybrid transport (transports advertise `["hybrid", "internal"]`). USB security keys (e.g., YubiKey-class), NFC-only authenticators, and Windows Hello are not yet covered. The transport-class filter excludes `["internal"]`-only credentials from `cross-platform`-policy tools regardless of vendor; non-Apple hardware should work but is not yet verification-tested.

## License

MIT. See [LICENSE](./LICENSE).

## Contributing

This repository is a reference implementation supporting an active SEP. Bug reports, questions, and discussion via GitHub Issues are welcome. For substantive design proposals or normative changes, the SEP PR is the right venue — the canonical surface is the spec, not the library API. Library-level fixes that align the implementation with the SEP are always appropriate.
