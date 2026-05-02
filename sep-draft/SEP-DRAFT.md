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

The Model Context Protocol provides advisory tool annotations and session-level authorization, but no mechanism for cryptographically binding a user-verified authenticator gesture to a specific tool invocation with specific arguments. For tool calls with high-stakes consequences — placing trades, deploying infrastructure, deleting data — a confirmation rendered by a potentially compromised client is insufficient: the same client or agent that issues the call can fabricate the approval gesture without meaningful human authorization.

This proposal introduces per-call verified approval. Tools mark themselves as requiring approval via the `_meta` annotation under the `io.modelcontextprotocol/verified-approval` key. Before invoking such a tool, the client requests a server-issued challenge whose value includes a hash of the canonicalized arguments. The user authorizes the call through a WebAuthn assertion bound to that challenge. The server independently verifies the signature, recomputes the action hash from the actual tool-call arguments, and rejects mismatches. The ceremony composes additively with existing MCP primitives: OAuth Authorization remains session-level; tool annotations remain advisory unless this proposal's annotation is present; elicitation remains the mechanism for routine and out-of-band data flows.

The proposal delivers cryptographically verified argument-binding, freshness, and single-use enforcement. It does not, on its own, defend against display-tampering attacks on synced credentials (per-call gestures may occur on the same device the client controls); the Security Implications section documents this residual risk and proposes future work. The reference implementation includes hardware-tested end-to-end ceremony, server-side verification, and a discriminated-outcome client API.

## 3. Motivation

### 3.1 The threat surface

A tool that places trades. A tool that deletes files. A tool that deploys to production. A tool that transfers money. These calls share a property: the wrong invocation is not a wrong answer the user can ignore — it is a state change that has already happened by the time anyone notices. For tools in this class, per-call human consent is reasonable.

The most common UX for that consent is a confirmation dialog rendered by the MCP client: a modal that names the tool, summarizes the arguments, and waits for a click. As an enforcement primitive, the dialog collapses under several common conditions:

- **Auto-approve modes**, where the user has pre-approved sessions of arbitrary tool use — the dialog never appears.
- **Compromised clients**, where the agent driving the LLM loop is the same process that owns the dialog and can dismiss it programmatically.
- **Prompt injection**, where a malicious tool output instructs the agent to "click yes" and the agent complies as if a user had.
- **Habitual confirmation**, where a user has clicked yes hundreds of times and clicks yes again without reading.

In each case, the client or agent that issues the call can simulate approval that the human did not meaningfully provide.

### 3.2 What MCP currently provides, and why each is insufficient

#### 3.2.1 Tool annotations (destructiveHint, etc.)

The MCP base spec defines tool annotations — `destructiveHint`, `readOnlyHint`, `idempotentHint`, `openWorldHint` — as advisory hints. The spec gives clients no obligation to surface them and no normative behavior tied to them. They are a UI affordance: a destructive-tool icon, a confirmation prompt the client may or may not render. These annotations serve their intended purpose. The verified-approval annotation introduced by this proposal (§4.2) is a separate mechanism that addresses a different threat model.

#### 3.2.2 OAuth Authorization

The MCP [authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization) defines session-level authorization: the user authorizes the client→server connection once, the client receives an access token, and subsequent tool calls present that token. There is no per-call human-consent mechanism. Once authorized, a client can invoke any tool the server exposes any number of times without further user interaction. Authorization answers "may this client connect" — not "did the user approve this call."

#### 3.2.3 Step-up authorization

The authorization spec includes a step-up flow: a tool call may return `403` with `insufficient_scope`, prompting the client to re-authorize for additional scopes. Step-up changes the *scope* the session holds, not the *individual approvals* within it. Once stepped up to `files:write`, the client can perform any number of file writes with no further interaction. The granularity is sustained access, not single actions.

#### 3.2.4 Elicitation, form mode

The MCP [elicitation spec](https://modelcontextprotocol.io/specification/2025-11-25/client/elicitation) defines a form mode for collecting structured input from the user through the client: a username, a date range. The spec explicitly forbids form-mode elicitation for sensitive data such as passwords or credentials. Form mode is a routine-input mechanism, not an approval mechanism, and the data passes through the same client whose trustworthiness is in question.

#### 3.2.5 Elicitation, URL mode

URL-mode elicitation is the closest existing primitive. It directs the user to an external URL for sensitive interactions that "must not pass through the MCP client" — authentication redirects, payment flows, credential collection. It differs structurally from per-call approval in three ways. First, it collects information *into* the server (credentials entered into a webpage), while per-call approval collects consent *for an action out of* the server. Second, it produces no argument-binding: the resulting token is reusable across subsequent calls, with no protocol-level tie between one authorization and one tool invocation. Third, it requires the server to host an externally reachable URL, while per-call approval works for any MCP server, including stdio-only servers. The two address adjacent but distinct problems and can coexist.

### 3.3 The specific gap

The gap is precise: per-call, argument-bound, cryptographically verified human approval. Each word rules out a different existing primitive. *Per-call* rules out OAuth and step-up authorization, which grant sustained access whose granularity is the session or the scope, not the invocation. *Argument-bound* rules out URL-mode elicitation, which can authenticate a user but cannot tie the result to a specific tool call with specific arguments. *Cryptographically verified* rules out tool annotations and form-mode elicitation, neither of which produces a signature the server can check. *Human approval* rules out anything signed by the agent itself, by an automated token, or by software-only flows with no separate human gesture. No existing MCP primitive satisfies all four conditions.

### 3.4 Why it matters now

The landscape that motivates this gap has shifted. MCP servers now connect LLM agents to financial APIs, cloud infrastructure, file systems, payment processors, internal datastores, and outbound communication channels. The blast radius of a compromised agent is no longer "wrong text generated" — it is money moved, infrastructure modified, customer data deleted, messages sent under the user's identity. Prompt injection has matured into a routine operational concern: tool outputs are untrusted input, and any guidance an agent reads from a tool result is potentially adversarial. The combination of higher-stakes tools and untrusted outputs means MCP deployments increasingly operate under a threat model that includes adversarial input during autonomous execution.

The gap has been recognized in prior community discussion. Discussions #581, #594, and #668 gesture at it from different angles — questions about cryptographic approval primitives, runtime authorization for sensitive actions, and the distinction between discovery filtering and execution-time consent. A more recent proposal at #689 (Secure Model Context Protocol) addresses agent identity and capability scoping with per-call envelope signatures from the agent's ephemeral key — a complementary security primitive that does not certify human consent. SMCP and per-call human approval compose cleanly: the former proves which agent is making a call; the latter proves which human approved it. The gap — cryptographically signed approvals from the human, not the agent — has remained open through subsequent MCP security proposals.

The rest of this document defines the mechanism. The Specification section defines a tool-side annotation that marks a tool as requiring approval, a server-issued challenge whose value includes a hash of the canonicalized arguments, a WebAuthn ceremony that produces a signature bound to that challenge, and server-side verification that recomputes the action hash from the actual call and rejects on mismatch. The proposal is structurally additive: tools that do not carry the annotation behave exactly as they do today, and clients that do not implement the ceremony interact with non-annotated tools exactly as they do today. The new behavior applies only when the annotation is present.

## 4. Specification

### 4.1 Overview of the ceremony

The verified-approval ceremony binds a single tool invocation to a fresh, server-issued challenge that the user signs through a WebAuthn authenticator. This subsection describes the end-to-end flow; later subsections specify the wire formats, methods, and verification rules.

The flow assumes the server has registered at least one tool whose listing carries the verified-approval annotation (§4.2), the server has declared the `verifiedApproval` capability in its `initialize` response (§4.3), and the user has previously enrolled at least one credential through the enrollment ceremony (§4.4).

When an agent or user requests invocation of an annotated tool, the client requests a challenge from the server via `approval/challenge/create` (§4.4.3), supplying the tool name and the proposed arguments. The server canonicalizes the arguments, computes an action hash bound to `(toolName, canonicalArguments, serverId)` per §4.6, allocates a single-use challenge identifier with an expiration time, and returns a challenge envelope. The wire challenge bytes — those the authenticator signs over — encode a fresh nonce concatenated with the action hash. The envelope around these bytes additionally carries `displayText` describing the action, an `expiresAt` timestamp, and the WebAuthn `requestOptions` the client passes to the browser API.

The client presents `displayText` to the user verbatim and invokes a WebAuthn assertion. The user authenticates through whatever gesture the authenticator requires — a biometric, a hardware key tap, or equivalent — producing a signed assertion bound to the wire challenge bytes. The client then invokes `tools/call` with the original arguments and the assertion carried in `params._meta["io.modelcontextprotocol/verified-approval"]` per §4.5.

The server is the verifier. On receiving the call, the server independently performs three checks: (a) it verifies the WebAuthn signature against the public key of the credential identified in the assertion response, (b) it recomputes the action hash from the actual call arguments and confirms it matches the hash committed to in the issued challenge, and (c) it atomically consumes the challenge so it cannot be replayed. The order matters: verification precedes consumption, so a call presenting an invalid signature does not consume the challenge it claims to bind. Only after all three checks succeed does the server execute the tool. Any failure rejects with the structured error of §4.10 and the tool is not executed.

```mermaid
sequenceDiagram
    participant User
    participant Client
    participant Server
    participant Authenticator

    Note over Client,Server: initialize: server declares verifiedApproval capability
    Note over User,Authenticator: prerequisite: at least one credential enrolled

    Client->>Server: tools/list
    Server-->>Client: tool listing with verified-approval _meta annotation

    Client->>Server: approval/challenge/create (toolName, arguments)
    Server-->>Client: challenge (nonce + actionHash, displayText, expiresAt)

    Client->>User: present displayText
    User->>Authenticator: gesture (biometric / hardware tap)
    Authenticator-->>Client: signed assertion bound to challenge

    Client->>Server: tools/call (name, arguments, _meta evidence)
    Server->>Server: verify signature → recompute action hash → consume challenge
    Server-->>Client: tool result (or structured approval error)
```

The ceremony delivers three load-bearing properties. The signature certifies the specific canonicalized arguments (*argument-binding*), so swapping arguments between the user gesture and the server call fails verification. Challenges expire and are single-use (*freshness*), so a captured assertion cannot be reused beyond its issued challenge. The tool's declared authenticator class is enforced at enrollment and at challenge issuance (*capability filtering*). §8 documents the threat-model boundaries of these properties and the known residual risks.

### 4.2 Tool annotation: `tool._meta["io.modelcontextprotocol/verified-approval"]` shape

A server marks a tool as requiring verified approval by setting a value at the namespaced `_meta` key `"io.modelcontextprotocol/verified-approval"` on the tool's listing entry. The value has the following shape:

```typescript
interface VerifiedApprovalToolMeta {
  required: "verified";
  authenticatorClass?: "cross-platform" | "platform";
}
```

`required: "verified"` is the literal string that marks the tool as gated. `authenticatorClass`, when present, declares which class of credentials the tool accepts; the semantics of each class are specified in §4.7.

A tool listing carrying this annotation looks as follows on the wire:

```json
{
  "name": "delete_resource",
  "title": "Delete resource",
  "description": "Permanently delete the resource with the given id.",
  "inputSchema": {
    "type": "object",
    "required": ["resourceId"],
    "additionalProperties": false,
    "properties": {
      "resourceId": { "type": "string", "minLength": 1 }
    }
  },
  "_meta": {
    "io.modelcontextprotocol/verified-approval": {
      "required": "verified",
      "authenticatorClass": "cross-platform"
    }
  }
}
```

Normative requirements:

- Servers MUST set `required` to the literal string `"verified"` when the tool requires verified approval. Future versions of this specification MAY define additional values.
- The `authenticatorClass` field is OPTIONAL. When omitted, clients and servers SHOULD treat the policy as `"cross-platform"`.
- Clients MUST treat tools without this annotation as not requiring verified approval; the tool is invoked as any other tool would be, with no additional ceremony.
- Servers MAY include additional fields under the `"io.modelcontextprotocol/verified-approval"` namespace key for forward compatibility. Clients MUST NOT reject the annotation because of unknown sibling fields and MUST tolerate them.

### 4.3 Capability declaration in `initialize`

Servers that support the verified-approval extension MUST declare the capability in their `initialize` response. The capability lives under the `extensions` slot of `ServerCapabilities` at the bare key `"verifiedApproval"`:

```json
{
  "capabilities": {
    "tools": {},
    "extensions": {
      "verifiedApproval": {}
    }
  }
}
```

The capability key inside `extensions` is the bare string `"verifiedApproval"` — not the reverse-DNS form used for the `_meta` annotation key. The asymmetry between the closed `extensions` namespace and the open `_meta` namespace is documented in `docs/DECISIONS.md` ("Capability declaration placement under `extensions`"). The empty-object value is the initial declaration shape; future versions of this specification MAY define sub-fields under it.

Normative requirements:

- A server that registers any tool carrying the verified-approval annotation MUST declare this capability in its `initialize` response.
- A server MAY declare the capability without yet having registered any approval-required tool — for example, in implementations where tools are loaded dynamically post-`initialize`.
- Declaring the capability commits the server to understanding the methods defined in §4.4 (`approval/enroll/begin`, `approval/enroll/finish`, `approval/challenge/create`) and to accepting and verifying the request-side evidence shape defined in §4.5.
- Clients MUST tolerate unknown sub-fields under the capability value without rejecting the declaration.
- A tool listing carrying this annotation while its server has not declared the capability is a server-side inconsistency. Clients SHOULD log this and MAY refuse to invoke the tool. Servers MUST NOT register approval-required tools without declaring the capability.
- If a client invokes an approval-required tool against a server that declared this capability without including evidence at `params._meta["io.modelcontextprotocol/verified-approval"]`, the server MUST reject the call with the structured error specified in §4.10 (the missing-evidence reason).

### 4.4 New methods

This proposal introduces three JSON-RPC methods following the standard MCP method-naming convention — slash-separated, no reverse-DNS prefix because they are spec-level methods rather than vendor extensions. The methods form two ceremonies: *enrollment* (`approval/enroll/begin` and `approval/enroll/finish`, run once per credential) and *challenge issuance* (`approval/challenge/create`, run before each annotated tool call). All three require the server to have declared the verified-approval capability per §4.3; a server that has not declared the capability MUST respond with JSON-RPC error `-32601` ("Method not found") to any of these methods.

#### 4.4.1 `approval/enroll/begin`

This method initiates WebAuthn credential registration. The server constructs the WebAuthn `PublicKeyCredentialCreationOptionsJSON` object that the client passes to `navigator.credentials.create()`.

**Request.** This method takes no parameters. The `params` field, if present, MUST be ignored.

**Response.** A single field `options` carrying the WebAuthn creation options:

```json
{
  "options": {
    "rp": { "id": "example.com", "name": "Example RP" },
    "user": {
      "id": "<base64url userHandle>",
      "name": "alice@example.com",
      "displayName": "Alice"
    },
    "challenge": "<base64url 32-byte registration challenge>",
    "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
    "timeout": 300000,
    "attestation": "none",
    "excludeCredentials": [
      { "type": "public-key", "id": "<base64url credentialId>", "transports": ["usb"] }
    ],
    "authenticatorSelection": {
      "residentKey": "preferred",
      "userVerification": "required"
    }
  }
}
```

Fields under `options` follow the WebAuthn Level 3 specification ([https://www.w3.org/TR/webauthn-3/](https://www.w3.org/TR/webauthn-3/)) for `PublicKeyCredentialCreationOptionsJSON`. This proposal constrains a subset of those fields; the rest are at the server's discretion.

Normative requirements:

- Servers MUST issue a fresh registration challenge per call. Reusing a challenge across calls is a protocol violation.
- Servers MUST track the registration challenge so the corresponding `approval/enroll/finish` call can verify against it.
- Servers MUST set `authenticatorSelection.userVerification` to `"required"` so a presence-only authenticator gesture cannot complete enrollment.
- Servers SHOULD set a TTL on the registration challenge; if unstated, implementations SHOULD default to 5 minutes.
- The response MUST include `excludeCredentials` listing the user's already-enrolled credential IDs — an empty array if no credentials are enrolled. This causes the WebAuthn layer in the browser to refuse re-enrollment of the same authenticator before reaching the server. Server-side defense-in-depth against `excludeCredentials` bypass is specified in §4.4.2.

#### 4.4.2 `approval/enroll/finish`

This method completes WebAuthn credential registration. The client sends the registration response from `navigator.credentials.create()`; the server verifies it against the challenge issued by the corresponding `approval/enroll/begin` call and, on success, persists the new credential.

**Request.** A `params` object with a single `response` field carrying the WebAuthn registration response (`PublicKeyCredentialAttestationResponseJSON` per the WebAuthn Level 3 spec):

```json
{
  "response": {
    "id": "<base64url credentialId>",
    "rawId": "<base64url credentialId>",
    "type": "public-key",
    "response": {
      "clientDataJSON": "<base64url>",
      "attestationObject": "<base64url>",
      "transports": ["usb"]
    },
    "authenticatorAttachment": "cross-platform",
    "clientExtensionResults": {}
  }
}
```

**Response.** A confirmation object identifying the newly-stored credential:

```json
{
  "success": true,
  "credentialId": "<base64url credentialId>",
  "createdAt": "<ISO-8601 timestamp>"
}
```

Normative requirements:

- Servers MUST verify the registration response against the challenge issued by the corresponding `approval/enroll/begin`. Mismatched challenges MUST be rejected.
- Servers MUST verify that the authenticator performed user verification. A credential whose registration response did not assert UV MUST be rejected.
- Servers MUST verify the registration response is well-formed and that its embedded signature is valid. Servers using `attestation: "none"` MUST still perform this verification — `"none"` waives only the requirement to validate the attestation issuer's identity, not the requirement to verify the response itself.
- Servers MUST persist the credential's `publicKey`, `credentialId`, `counter`, `transports`, and `userHandle` for use during subsequent assertions.
- Servers MUST reject registration if the `credentialId` is already enrolled. This is server-side defense-in-depth: the WebAuthn-layer `excludeCredentials` enforcement at the browser is bypassable when the attestation does not sign over `clientDataJSON`, so the server MUST independently check for re-enrollment after WebAuthn verification but before persisting the new record. Reject with the structured error from §4.10 (the credential-already-enrolled reason).
- Servers MUST reject registration if the registration challenge has expired or has already been consumed.

#### 4.4.3 `approval/challenge/create`

This method is invoked by the client immediately before each call to a tool requiring verified approval. The server constructs a challenge envelope binding the proposed call's arguments to a fresh nonce; the envelope contains the WebAuthn `PublicKeyCredentialRequestOptionsJSON` the client passes to `navigator.credentials.get()`.

**Request.** A `params` object with two fields:

- `toolName`: the name of the tool to be invoked.
- `arguments`: the proposed arguments object.

```json
{
  "toolName": "delete_resource",
  "arguments": { "resourceId": "abc123" }
}
```

**Response.** A challenge envelope:

```json
{
  "challengeId": "<server-issued opaque identifier>",
  "displayText": "Permanently delete resource abc123",
  "expiresAt": "<ISO-8601 timestamp>",
  "requestOptions": {
    "challenge": "<base64url 64-byte (nonce || actionHash)>",
    "rpId": "example.com",
    "allowCredentials": [
      { "type": "public-key", "id": "<base64url credentialId>", "transports": ["usb"] }
    ],
    "userVerification": "required",
    "timeout": 60000
  }
}
```

Field semantics:

- `challengeId`: an opaque server-issued identifier; the client echoes it back in the evidence on `tools/call` (§4.5). Used by the server to look up the pending challenge state at verification time.
- `displayText`: a human-readable description of the action being approved. The client SHOULD present this verbatim to the user in the approval surface.
- `expiresAt`: an ISO-8601 timestamp after which the challenge is no longer accepted.
- `requestOptions`: the WebAuthn `PublicKeyCredentialRequestOptionsJSON` for the client to pass to `navigator.credentials.get()`. The `challenge` field encodes the wire challenge bytes — `nonce || actionHash` — that the authenticator signs over.

Normative requirements:

- Servers MUST verify that the named tool is registered with the verified-approval annotation per §4.2. If not, reject with the appropriate structured error from §4.10.
- Servers MUST canonicalize the supplied arguments per §4.6 before computing the action hash.
- Servers MUST compute the action hash from `(toolName, canonicalArguments, serverId)` per §4.6.
- Servers MUST construct the wire challenge bytes as `nonce || actionHash` — a 32-byte fresh nonce concatenated with the 32-byte action hash — and base64url-encode them into `requestOptions.challenge`.
- The nonce MUST be cryptographically random (drawn from a CSPRNG) and MUST be unique across all challenges issued by the server. Predictable or repeated nonces compromise the freshness property defined in §8.2.2.
- Servers MUST associate the challenge server-side with the tuple `(toolName, canonicalArguments, serverId)` so the verification rules in §4.8 can recompute and compare at call time.
- Servers SHOULD set `expiresAt` no further in the future than a server-defined TTL; if unstated, implementations SHOULD default to 60 seconds.
- Servers MUST populate `requestOptions.allowCredentials` with the user's enrolled credentials filtered by the tool's `authenticatorClass` policy per §4.7.
- Servers MUST set `requestOptions.userVerification` to `"required"`.
- Servers MUST construct `displayText` from a server-side describe function applied to the supplied arguments. The `displayText` MUST be human-readable and accurately describe the action being approved. This is security-relevant — the user's understanding of what they are signing depends on it matching the action hash bound by the same call. See §8 on display tampering for the threat-model boundaries of this guarantee.
- Clients MUST present `displayText` to the user verbatim before invoking the WebAuthn assertion. The displayText is the user's authoritative description of the action being approved; transformations of it (truncation, paraphrasing, omission) defeat the human-understanding property the proposal targets.

### 4.5 Evidence on `tools/call`: `params._meta["io.modelcontextprotocol/verified-approval"]`

When invoking a tool whose listing carries the verified-approval annotation, the client MUST attach the WebAuthn assertion in the request's `_meta` field at the namespaced key `"io.modelcontextprotocol/verified-approval"`. The value at this key has the shape:

```typescript
interface ApprovalEvidence {
  method: "webauthn";
  challengeId: string;
  response: AuthenticationResponseJSON;
}
```

Field semantics:

- `method`: the discriminator identifying the assertion family. Today the only conformant value is `"webauthn"`. Future versions of this specification MAY define additional values.
- `challengeId`: the identifier from the matching `approval/challenge/create` response. Used by the server to look up the pending challenge state.
- `response`: the WebAuthn `PublicKeyCredentialAuthenticationResponseJSON` produced by `navigator.credentials.get()`, unmodified.

A complete `tools/call` request carrying evidence:

```json
{
  "method": "tools/call",
  "params": {
    "name": "delete_resource",
    "arguments": { "resourceId": "abc123" },
    "_meta": {
      "io.modelcontextprotocol/verified-approval": {
        "method": "webauthn",
        "challengeId": "<challengeId from approval/challenge/create>",
        "response": {
          "id": "<base64url credentialId>",
          "rawId": "<base64url credentialId>",
          "type": "public-key",
          "response": {
            "clientDataJSON": "<base64url>",
            "authenticatorData": "<base64url>",
            "signature": "<base64url>",
            "userHandle": "<base64url>"
          },
          "authenticatorAttachment": "cross-platform",
          "clientExtensionResults": {}
        }
      }
    }
  }
}
```

Normative requirements:

- Clients MUST include this evidence in `params._meta` for every call to a tool that carries the verified-approval annotation.
- Clients MUST set `method` to the literal string `"webauthn"`.
- Clients MUST set `challengeId` to the value received from the immediately preceding `approval/challenge/create` for the same tool and arguments. Each `challengeId` is bound to exactly one `tools/call` invocation; a client that submits the same `challengeId` in two distinct `tools/call` requests is in protocol violation, and the server's single-use enforcement (§4.8) will reject the second submission with the appropriate structured error from §4.10.
- Clients MUST forward the WebAuthn assertion response unmodified.
- Servers MUST verify the evidence per the verification rules in §4.8 before executing the tool.
- Servers MUST reject the call with the structured error from §4.10 when evidence is missing, malformed, or fails any verification step.
- Servers MUST NOT execute the tool if any verification step fails.

### 4.6 Argument canonicalization (RFC 8785) and action-hash construction

This proposal uses RFC 8785 (JSON Canonicalization Scheme, JCS) for argument canonicalization. JCS produces a single, deterministic byte sequence for any JSON value, with sorted object keys, normalized number serialization, and UTF-8 NFC normalization where applicable. Both client and server MUST use RFC 8785 verbatim — implementation-specific variants of "deterministic JSON" are non-conformant.

Canonicalization is applied to the validated arguments object that will be passed to the tool's execution handler — the same object processed by the tool's `inputSchema` (defaults applied, type coercions performed) at the MCP layer. Canonicalization is NOT applied to the raw JSON bytes received from the client; clients and servers may differ in how they format that JSON, but the validated logical object canonicalizes to the same bytes on both sides.

The action hash binds three inputs — the tool name, the canonicalized arguments, and the per-server identifier — into a single 32-byte SHA-256 digest:

```
actionHashBytes = SHA-256( utf8(toolName) || 0x00
                           || utf8(canonicalArgsJson) || 0x00
                           || utf8(serverId) )                  // 32 bytes
```

The 0x00 byte separates the three fields. A 0x00 byte cannot appear inside a valid UTF-8 identifier or inside JCS output of a JSON value, so the separator is unambiguous: no input could blur the boundaries between fields. The wire challenge bytes (`nonce || actionHash`, base64url-encoded into the WebAuthn challenge field) are constructed per §4.4.3.

`serverId` is an implementation-defined per-server identifier baked into the hash so a challenge issued by server A cannot be replayed against server B even if both have enrolled the same credential. Implementations MAY derive `serverId` from the OAuth issuer URL, a configured constant, or any other stable per-server string. What matters normatively is that distinct servers produce distinct `serverId` values.

Normative requirements:

- Both client and server MUST use RFC 8785 (JCS) for argument canonicalization.
- Both MUST use SHA-256 for the action hash.
- The action hash MUST be computed as `SHA-256(utf8(toolName) || 0x00 || utf8(canonicalArgsJson) || 0x00 || utf8(serverId))` with the 0x00 byte as separator.
- Servers MUST keep `serverId` stable across the lifetime of issued challenges; rotating `serverId` while challenges are pending invalidates them.
- Canonicalization MUST be applied to the validated arguments object passed to the tool's execution handler, not to the raw JSON bytes received from the client.

### 4.7 Authenticator class policy: capability filter

The verified-approval annotation's optional `authenticatorClass` field declares which class of credentials the tool accepts. Two values are defined:

- `"cross-platform"` (the default when `authenticatorClass` is omitted): credentials whose stored transports include at least one of `hybrid`, `usb`, `nfc`, or `ble` are eligible. Credentials whose transports are exclusively `["internal"]` (same-device-only authenticators such as platform biometrics) are excluded.
- `"platform"`: any enrolled credential is eligible, including same-device-only authenticators.

The filter is applied at two points in the ceremony:

- At enrollment-time, via the registration-options `authenticatorSelection` constraints.
- At challenge-issuance time, via the `allowCredentials` list on the WebAuthn assertion options. Credentials whose transports do not satisfy the policy are excluded from `allowCredentials`, so the browser will not invoke them for signing.

This is a CAPABILITY filter, not a use-time guarantee. The cross-platform policy excludes credentials advertised as same-device-only; it does not constrain which device the user actually signs on. With synced-credential providers (iCloud Keychain, Google Password Manager, etc.), a credential whose transports include both `"hybrid"` and `"internal"` is locally usable on the device hosting the client, and the OS picker may present the local presentation path regardless of server-issued WebAuthn hints. The cross-platform filter correctly excludes credentials whose transports advertise only `["internal"]`. It does not exclude credentials whose transports advertise `["hybrid", "internal"]` — even when the OS picker may present those credentials via the local device path. Synced-credential providers (iCloud Keychain, Google Password Manager) typically advertise `["hybrid", "internal"]` because the credential is reachable via cross-device flows OR locally; the filter, applied to the advertised transports, cannot distinguish which of those paths the user will actually take. Mitigating display-tampering on synced credentials requires platform-side changes (per-call attestation of the transport actually used at sign time, out-of-band confirmation channels, etc.) and is documented as Future Work in §8.4.

Normative requirements:

- When `authenticatorClass` is `"cross-platform"` or omitted, servers MUST exclude credentials from `allowCredentials` whose stored transports are exclusively `["internal"]`.
- When `authenticatorClass` is `"platform"`, servers MUST accept any enrolled credential.
- Servers MUST apply the filter both at enrollment-time and at challenge-issuance time per the two-point flow above.
- The filter has no client-side normative requirement; clients are not expected to participate in or replicate the policy check.

### 4.8 Server verification rules (normative MUST list)

Servers MUST perform the following checks in order when handling a `tools/call` request to a tool carrying the verified-approval annotation. Each check has a corresponding §4.10 reason; on failure, the server MUST reject with that reason and MUST NOT proceed to subsequent checks.

1. Evidence MUST be present at `params._meta["io.modelcontextprotocol/verified-approval"]`. Missing → `missing_evidence`.
2. Evidence MUST be a well-formed object with `method`, `challengeId`, and `response`. Malformed → `missing_evidence`.
3. `evidence.method` MUST be `"webauthn"`. Other → `unsupported_method`.
4. The challenge `evidence.challengeId` MUST be known. Unknown → `challenge_unknown`.
5. The challenge MUST NOT have been consumed. Consumed → `challenge_consumed`.
6. The challenge MUST NOT have expired (current time < `expiresAt`). Expired → `challenge_expired`.
7. The challenge MUST have been issued for the tool currently being invoked. Mismatch → `challenge_wrong_tool`.
8. The credential `evidence.response.id` MUST be enrolled. Unknown → `unknown_credential`.
9. The credential's transports MUST satisfy the tool's `authenticatorClass` policy per §4.7. Mismatch → `authenticator_class_mismatch`.
10. The WebAuthn signature MUST verify against the credential's stored public key. Failed → `signature_verification_failed`.
11. The credential's signCount MUST be strictly greater than the stored counter when the stored counter is greater than zero. A stored counter of zero disables this check; this accommodates synced credentials (e.g., iCloud Keychain passkeys) that report counter values of zero indefinitely. Regression → `signature_counter_regression`.
12. The action hash recomputed from `(toolName, canonicalArguments, serverId)` per §4.6 MUST equal the action hash committed in the issued challenge. Mismatch → `argument_hash_mismatch`.
13. The challenge MUST be atomically consumed after all preceding checks succeed. Consume-then-verify implementations are non-conformant — a captured assertion replayed against a still-valid challenge would consume the challenge before the failing verification surfaces, leaving the legitimate next call unable to use it.
14. The credential's stored counter MUST be updated to the value reported in the assertion.

The order of these checks is normative for steps 1-13. Verification (1-12) MUST precede consumption (13). The challenge-state checks (4-7) follow the order unknown → consumed → expired → wrong-tool to give callers the most specific reason available.

Successful completion of steps 1-14 produces the verified-approval primitive's deliverable: a binary attestation that this specific call is authorized. The tool's execution itself is NOT part of this ceremony. The caller — typically the server's `tools/call` handler — is responsible for invoking the tool's execute handler only after verification returns successfully. This separation makes clear what the proposal delivers (authorization for a specific call) and what it does not (the execution itself, which has its own failure modes outside this proposal's scope).

### 4.9 Client behavior rules (normative MUST list)

This subsection consolidates client-side normative requirements introduced in earlier subsections; cross-references identify the originating subsection.

- Clients MUST detect tools carrying the verified-approval annotation per §4.2.
- Clients MUST NOT invoke an approval-required tool without first requesting a challenge via `approval/challenge/create` per §4.4.3.
- Clients MUST present `displayText` to the user verbatim before invoking the WebAuthn assertion per §4.4.3. Transformations of `displayText` (truncation, paraphrasing, omission) defeat the human-understanding property the proposal targets.
- Clients MUST forward the WebAuthn assertion response unmodified per §4.5.
- Clients MUST attach the assertion evidence at `params._meta["io.modelcontextprotocol/verified-approval"]` on the `tools/call` request per §4.5.
- Clients MUST NOT reuse a `challengeId` across `tools/call` invocations per §4.5; each `challengeId` is bound to exactly one call.
- Clients MUST invoke the WebAuthn assertion only after the user has reviewed `displayText`.
- Clients SHOULD surface §4.10 errors to the user with appropriate context. The specific UX is implementation-defined; this is a SHOULD because the choice of presentation (modal, toast, log entry) depends on the client's broader interface conventions.

### 4.10 Error codes and reasons

All approval-domain rejections use the JSON-RPC error code `-32001`. JSON-RPC 2.0 reserves codes -32000 to -32099 for implementation-defined server errors; this proposal occupies one slot in that range. The error structure follows JSON-RPC convention: a top-level `error` object with `code`, a human-readable `message`, and a structured `data` object containing a `reason` field. The `reason` field is the canonical machine-readable discriminator; clients SHOULD branch on it rather than parsing `message`.

```json
{
  "jsonrpc": "2.0",
  "id": "<request id>",
  "error": {
    "code": -32001,
    "message": "Approval evidence does not match the arguments of this call",
    "data": {
      "reason": "argument_hash_mismatch"
    }
  }
}
```

The `reason` field carries one of the values enumerated below, grouped by the path that emits it.

**Per-call assertion path** (emitted during `tools/call` verification, §4.8):

- `missing_evidence` — evidence is missing from `params._meta` or its shape is malformed.
- `unsupported_method` — `evidence.method` is not `"webauthn"`.
- `challenge_unknown` — `challengeId` does not match any pending challenge.
- `challenge_consumed` — the challenge has already been used.
- `challenge_expired` — the challenge's `expiresAt` has passed.
- `challenge_wrong_tool` — the challenge was issued for a different tool.
- `unknown_credential` — the credential identified in the assertion is not enrolled.
- `authenticator_class_mismatch` — the credential's class does not satisfy the tool's policy.
- `signature_verification_failed` — WebAuthn signature verification failed.
- `signature_counter_regression` — the credential's signCount did not strictly increase.
- `argument_hash_mismatch` — the recomputed action hash does not match the challenge's committed hash.

**Challenge issuance** (emitted by `approval/challenge/create`, §4.4.3):

- `tool_not_approved_required` — challenge requested for a tool not registered as approval-required.
- `no_eligible_credential` — no enrolled credentials satisfy the tool's `authenticatorClass` policy.

**Enrollment finish** (emitted by `approval/enroll/finish`, §4.4.2):

- `credential_already_enrolled` — re-enrollment of an already-enrolled credentialId.
- `no_pending_enrollment` — no `approval/enroll/begin` was called or its challenge expired.
- `verification_failed` — WebAuthn registration verification failed.

Normative requirements:

- Servers MUST use code `-32001` for all approval-domain rejections.
- Servers MUST include a `reason` field in `data` from the enumerated set above.
- Servers MAY include additional fields in `data` for diagnostic purposes (timestamps, counter values, etc.). Clients MUST NOT depend on additional fields beyond `reason`.
- Implementations MAY localize `message`. The `reason` field is the canonical machine-readable identifier and MUST NOT be localized.

### 4.11 Security relationship to existing primitives

Verified approval is structurally additive: it composes with existing MCP primitives without conflict.

**OAuth Authorization** (§3.2.2) and verified approval operate at different layers. OAuth establishes that a client may connect to a server at all (session-level). Verified approval establishes that a specific tool call has been authorized by a specific human-bound credential (per-call, argument-bound). Both apply to every approval-required call: OAuth authenticates the connection; verified-approval evidence authorizes the individual call. Neither replaces the other.

**Step-up authorization** (§3.2.3) escalates session *scope*; verified approval escalates a *single call*. The two are not in conflict — a client MAY step up to gain a broader scope and then perform many calls under it, with only those to verified-approval-annotated tools requiring per-call evidence. Step-up affects what a session may do; verified approval affects which individual actions within a permitted session are authorized.

**Elicitation** (§3.2.4 and §3.2.5) is a routine and out-of-band input mechanism. Form-mode elicitation collects routine input through the client; URL-mode elicitation collects sensitive input out-of-band; verified approval collects per-call human consent for an action. A single server may use all three: elicit routine input via form mode, redirect to a URL for a payment authorization, and require verified approval for the most consequential tool calls. The three address adjacent but distinct problems.

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

- Tools without an `io.modelcontextprotocol/verified-approval` `_meta` annotation behave identically.
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
