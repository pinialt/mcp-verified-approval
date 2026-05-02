# SEP-XXXX: Verified Approval for MCP Tool Calls

```
SEP: XXXX
Title: Verified Approval for MCP Tool Calls
Author: TBD
Status: Draft
Type: Standards Track
Created: 2026-05-02
PR: TBD
Supersedes: TBD
Updates: TBD
```

## 1. Preamble

- Title, author, status (draft), type (Standards Track), created, PR number, superseded/updates fields.

## 2. Abstract

The Model Context Protocol provides advisory tool annotations and session-level authorization, but no mechanism for cryptographically verifying that a specific human consented to a specific tool invocation with specific arguments. For tool calls with high-stakes consequences — placing trades, deploying infrastructure, deleting data — a confirmation rendered by a potentially compromised client is insufficient: an agent driving the same client can approve its own prompts.

This proposal introduces per-call verified approval. Tools mark themselves as requiring approval via a `_meta.verifiedApproval` annotation. Before invoking such a tool, the client requests a server-issued challenge whose value includes a hash of the canonicalized arguments. The user authorizes the call through a WebAuthn assertion bound to that challenge. The server independently verifies the signature, recomputes the action hash from the actual tool-call arguments, and rejects mismatches. The ceremony composes additively with existing MCP primitives: OAuth Authorization remains session-level; tool annotations remain advisory unless this proposal's annotation is present; elicitation remains the mechanism for routine and out-of-band data flows.

The proposal delivers cryptographically verified argument-binding, freshness, and single-use enforcement. It does not, on its own, defend against display-tampering attacks on synced credentials (per-call gestures may occur on the same device the client controls); the Security Implications section documents this residual risk and proposes future work. The reference implementation includes hardware-tested end-to-end ceremony, server-side verification, and a discriminated-outcome client API.

## 3. Motivation

### 3.1 The threat surface

- Agentic MCP tool calls execute autonomously within an authorized session. Some tools (trades, deletions, deployments, payments) have consequences that justify per-call human consent.
- The existing UX pattern — client-rendered confirmation prompt — collapses against compromised clients, auto-approve modes, and prompt-injected approval flows.

### 3.2 What MCP currently provides, and why each is insufficient

#### 3.2.1 Tool annotations (destructiveHint, etc.)

- Advisory, no enforcement primitive.

#### 3.2.2 OAuth Authorization

- Session-level, not per-call.

#### 3.2.3 Step-up authorization

- Escalates scopes, not individual approvals.

#### 3.2.4 Elicitation, form mode

- Schema-validated input through the client.

#### 3.2.5 Elicitation, URL mode

- Out-of-band, but for collecting info into the server, not consent for actions out of it; no argument binding.

### 3.3 The specific gap

- Per-call, argument-bound, cryptographically verified human approval — no existing primitive provides this.

### 3.4 Why it matters now

- Brief: agentic deployments scaling, money/infra/data tools proliferating, prompt injection landscape maturing. Cite the four discussions Theaxiom referenced.

## 4. Specification

### 4.1 Overview of the ceremony

- High-level walkthrough of the end-to-end flow.

### 4.2 Tool annotation: `_meta.verifiedApproval` shape

- Field definitions and example.

### 4.3 Capability declaration in `initialize`

- How servers and clients advertise support.

### 4.4 New methods

#### 4.4.1 `approval/enroll/begin`

- Request/response shape, semantics.

#### 4.4.2 `approval/enroll/finish`

- Request/response shape, semantics.

#### 4.4.3 `approval/challenge/create`

- Request/response shape, semantics.

### 4.5 Evidence on `tools/call`: `params._meta.verifiedApproval`

- Where the assertion travels, what the server expects.

### 4.6 Argument canonicalization (RFC 8785) and action-hash construction

- JCS, the hash input, the hash algorithm.

### 4.7 Authenticator class policy: capability filter

- How class is checked at enrollment, not at use.

### 4.8 Server verification rules (normative MUST list)

- Bullet list of MUSTs for the server.

### 4.9 Client behavior rules (normative MUST list)

- Bullet list of MUSTs for the client.

### 4.10 Error codes and reasons

- Enumerated codes and structured reasons.

### 4.11 Security relationship to existing primitives

- Composes with OAuth Authorization, distinct from URL mode elicitation.

## 5. Rationale

### 5.1 Why `_meta` over annotations

- Advisory vs normative.

### 5.2 Why JCS for canonicalization

- Determinism, ecosystem fit.

### 5.3 Why argument-binding via challenge field, not separate field

- Reasoning.

### 5.4 Why authenticator class is a capability filter, not a use-time guarantee

- Link to the empirical mitigation-1 finding.

### 5.5 Why per-call rather than per-session

- Reasoning.

### 5.6 Why method-agnostic envelope with WebAuthn as first profile

- Reasoning.

### 5.7 Considered alternatives and why rejected

- TOTP, push notifications, OIDC step-up, plain elicitation URL mode.

## 6. Backward Compatibility

- Tools without `_meta.verifiedApproval` annotation behave identically.
- Clients without `verifiedApproval` capability cannot invoke approval-required tools — the server SHOULD reject with a structured error.
- Servers SHOULD declare the capability in `initialize`.
- Migration path: existing tools opt in by adding the annotation.

## 7. Reference Implementation

- One paragraph linking to the repo, library, demo, test suite, and verification reports.
- Note that the implementation is end-to-end working and hardware-tested.
- Note that the library API mirrors the spec's normative shape.

## 8. Security Implications

### 8.1 Threat model

#### 8.1.1 Compromised MCP client (primary)

- Description.

#### 8.1.2 Prompt injection within an honest client

- Description.

#### 8.1.3 Network-layer attackers

- Covered by transport TLS.

#### 8.1.4 Compromised authenticator

- Hardware-rooted defense.

#### 8.1.5 Malicious server

- Out of scope; the user trusts the server they chose.

### 8.2 Properties delivered (with reasoning)

#### 8.2.1 Argument-binding via the challenge construction

- Reasoning.

#### 8.2.2 Freshness via per-call nonce and TTL

- Reasoning.

#### 8.2.3 Single-use via server-side atomic consume

- Reasoning.

#### 8.2.4 Capability filtering via authenticator class

- Reasoning.

### 8.3 Residual risks

#### 8.3.1 Display tampering for synced credentials

- The empirical finding; link to `verification/phase-4-mitigation-1.md`.

#### 8.3.2 Counter-zero credentials

- Apple synced passkey case; cloning detection degraded.

#### 8.3.3 Social engineering of the user gesture

- Out of protocol scope.

#### 8.3.4 Recovery flow

- Lost authenticator — implementation-defined.

### 8.4 Future Work / open spec questions

#### 8.4.1 Per-assertion transport observability

- Notes.

#### 8.4.2 Out-of-band confirmation channels

- Notes.

#### 8.4.3 Multi-party countersignature

- Notes.

#### 8.4.4 Headless agent contexts

- Delegated approval sessions.

<!-- No appendices in v1. Test vectors live in the reference implementation. -->
