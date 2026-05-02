// Root re-export: the SEP-quotable wire vocabulary, surfaced without
// requiring callers to pick a subpath. Implementation modules live at
// mcp-verified-approval/server and mcp-verified-approval/client.
export {
  VERIFIED_APPROVAL_TOOL_META_KEY,
  VERIFIED_APPROVAL_REQUEST_META_KEY,
  VERIFIED_APPROVAL_CAPABILITY_KEY,
  VERIFIED_APPROVAL_REQUIRED,
  VERIFIED_APPROVAL_CLASS_CROSS_PLATFORM,
  VERIFIED_APPROVAL_CLASS_PLATFORM,
  APPROVAL_CHALLENGE_CREATE_METHOD,
  APPROVAL_ENROLL_BEGIN_METHOD,
  APPROVAL_ENROLL_FINISH_METHOD,
  APPROVAL_ERROR_CODE,
  ApprovalEvidenceSchema,
  ApprovalChallengeSchema,
  canonicalArgs,
  computeActionHash,
  policyAcceptsTransports,
  type AuthenticatorClass,
  type VerifiedApprovalToolMeta,
  type ApprovalChallenge,
  type ApprovalEvidence,
  type ApprovalErrorReason,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialRequestOptionsJSONShape,
  type PublicKeyCredentialHint,
} from "./shared/index.js";
