# T1078 Incident Report

> Advisory: this report reads synthetic observables and does not assert that an account was compromised, that data was exfiltrated, or that impact occurred. Response actions are dry-run recommendations requiring human approval; none were executed.

## 1. Report identification

- Report ID: `159c22b3-cc37-5329-9513-bca76e3b01ed`
- Generated (deterministic report timestamp, derived from `finding.created_at`, not wall-clock export time): 2026-09-22T17:00:00+00:00
- Technique: T1078 (Valid Accounts)

## 2. Executive summary

Behaviour-based detection identified a correlated sequence of activity consistent with possible valid-account misuse (MITRE ATT&CK T1078) at confidence 90/100. This is a behavioural, analytic signal: investigation and validation have not confirmed account compromise, data exfiltration, or impact. All 16 detection-validation cases passed before this report was produced. The proposed response is dry-run-only and approval-gated; nothing was executed.

## 3. Scope and methodology

This report covers the exported normalized telemetry artefact for the T1078 scenario: 8 security events across 8 synthetic entities, centred on the single detection finding (compromised-identity-sequence). It compiles the finding, its supporting evidence, the chronological timeline, the evidence-led investigation, the dry-run response plan, and the detection-validation result. Only synthetic data are involved; no live system, account, session, permission, file, network, or security control was accessed or modified, and no response action was executed.

**Methodology**

1. Loaded the artefact with load_telemetry_artefact; no telemetry was regenerated.
2. Ran behaviour-based detection (detect_t1078) and asserted exactly one finding.
3. Ran the evidence-led investigation (investigate_t1078) across the finding's referenced events.
4. Ran deterministic response planning (plan_t1078_response) producing dry-run-only, approval-gated actions grouped by category.
5. Ran detection validation (validate_t1078) exactly once; the suite must pass before reporting.
6. Rendered this deterministic Markdown report from the workflow data above.

## 4. Finding

- Detection finding title (analytic label; not confirmation): "Compromised identity used from unfamiliar device"
- Detection rule: `compromised-identity-sequence`
- Technique: T1078
- Severity: high
- Status: new
- Confidence: 90/100
- Description: An identity with a known-good baseline later logged in from a new network and unfamiliar device, then performed a correlated set of suspicious behaviours within the correlation window.
- Detection rationale: Confidence 90/100 from login from a new network and unfamiliar device, repository enumeration, restricted file access, privileged-access request, archive creation, outbound network connection.

## 5. Involved entities

The account, unfamiliar device, resources, and external destination implicated by the finding.

| Role | Type | Identifier | Display name |
|---|---|---|---|
| Resource (archive) | file | workspace/export-20260922.zip | Synthetic Export Archive |
| Resource (restricted file) | file | repository/secrets/deployment-notes.txt | Deployment Notes |
| Resource (privileged access service) | application | privileged-access-service | Privileged Access Service |
| External destination | network_connection | 203.0.113.80:443 | Documentation Test Destination |
| Resource (repository) | application | source-repository | Source Repository |
| Account | account | alex.morgan@example.lab | Alex Morgan |
| Unfamiliar device | host | device-unknown-442 | Unfamiliar Device |

## 6. Chronological timeline

| # | Timestamp | Event ID | Summary |
|---|---|---|---|
| 1 | 2026-09-22T09:00:00+00:00 | 53374ee2-95d8-5b96-b74a-e57a0bee4a02 | Successful authentication from a known network and device |
| 2 | 2026-09-22T17:00:00+00:00 | c50ad28a-16fe-5560-b566-599bf31a4ea7 | Successful authentication from a new network and unfamiliar device |
| 3 | 2026-09-22T17:02:00+00:00 | d6d9ad03-7996-5640-b7eb-08fdd4c06b64 | Repository enumeration |
| 4 | 2026-09-22T17:04:00+00:00 | 5a64818c-facb-5e6d-a9e2-b06e1e7a5f85 | Restricted file access |
| 5 | 2026-09-22T17:06:00+00:00 | b66f8c34-ec4c-5f54-b389-c53a88c4191a | Privileged-access request |
| 6 | 2026-09-22T17:09:00+00:00 | 722c3574-d90c-58a7-bcf2-326ae66d8dd9 | Archive creation |
| 7 | 2026-09-22T17:12:00+00:00 | 46c1a7e1-5239-5586-b577-bf8516251bdd | Outbound network connection |

## 7. Evidence register

| Evidence ID | Source event ID | Relationship | Description |
|---|---|---|---|
| 346a1b6c-c6c4-5ef7-8af6-840b26a3d1ab | 53374ee2-95d8-5b96-b74a-e57a0bee4a02 | provides_context | Baseline context: the account authenticated successfully from a known network and device before the suspicious activity. |
| fc22e678-379d-5c1f-b0f8-12e7d253bbc8 | c50ad28a-16fe-5560-b566-599bf31a4ea7 | supports | The account authenticated successfully from a new network and unfamiliar device, anchoring the suspicious sequence. |
| fdb45817-9b9a-50f9-aa3a-a6489978ec58 | d6d9ad03-7996-5640-b7eb-08fdd4c06b64 | supports | Repository enumeration by the implicated identity. |
| a6e25c40-fc81-5853-86a0-f1fe5e9f2d98 | 5a64818c-facb-5e6d-a9e2-b06e1e7a5f85 | supports | Restricted file access by the implicated identity. |
| 9b2ece9a-2ff3-5e0e-9d27-197bf3195428 | b66f8c34-ec4c-5f54-b389-c53a88c4191a | supports | Privileged-access request by the implicated identity. |
| 3d97d7c1-e85c-5c32-a0c3-d8f75a88a42f | 722c3574-d90c-58a7-bcf2-326ae66d8dd9 | supports | Archive creation by the implicated identity. |
| 2192d433-8996-5b67-bef2-f164ea13fad7 | 46c1a7e1-5239-5586-b577-bf8516251bdd | supports | Outbound network connection by the implicated identity. |

## 8. Analysis

### 8.1 Confirmed facts

- The account authenticated successfully from a known network and device.
- The account authenticated successfully from a new network and unfamiliar device.
- Repository content was enumerated.
- A restricted file was accessed.
- A privileged-access request was made.
- An archive was created.
- An outbound network connection was observed.

### 8.2 Analyst assessments

- The new-context login followed by a correlated set of behaviours is consistent with possible valid-account misuse (MITRE ATT&CK T1078).
- This is a behavioural signal; impact, exfiltration, and account compromise are not confirmed by investigation alone.

### 8.3 Unresolved questions

- Did the account owner perform the new-context login and follow-on behaviours?
- Was any restricted file or archive exfiltrated during the session?
- Was the requested privileged access granted, and did it persist?

## 9. Recommended response

**DRY RUN ONLY — APPROVAL REQUIRED — NOT EXECUTED.** These are recommendations, not performed actions.

### 9.1 Containment

- **disable-account** [risk: high]
  - Purpose: If the behaviour is consistent with possible valid-account misuse (MITRE ATT&CK T1078), not a confirmed compromise, suspend the account to stop further activity while it is verified. This is a recommendation to evaluate, not an assertion that the account was compromised.
  - Execution: dry run only; approval required; not executed
  - Status: planned (not executed)
  - Verification: Confirm whether the account can no longer authenticate and record downstream service impact before any approval.
  - Rollback: Re-enable the account only after ownership and access safety are verified.

- **revoke-active-sessions** [risk: medium]
  - Purpose: If the behaviour is consistent with possible valid-account misuse (MITRE ATT&CK T1078), not a confirmed compromise, invalidate the account's active sessions so an unfamiliar device cannot remain logged in. Revoked sessions cannot be restored; this does not undo access permanently.
  - Execution: dry run only; approval required; not executed
  - Status: planned (not executed)
  - Verification: Confirm that no active sessions remain for the account on the unfamiliar device.
  - Rollback: Not applicable — no rollback guidance

- **deny-unfamiliar-device** [risk: medium]
  - Purpose: If the behaviour is consistent with possible valid-account misuse (MITRE ATT&CK T1078), not a confirmed compromise, deny authentication from the unfamiliar device pending verification of its ownership.
  - Execution: dry run only; approval required; not executed
  - Status: planned (not executed)
  - Verification: Confirm the unfamiliar device can no longer authenticate to the account.
  - Rollback: Re-allow the device only after device ownership and security posture are verified.

### 9.2 Evidence preservation

- **preserve-telemetry-artefact** [risk: low]
  - Purpose: Retain an immutable copy and a recorded hash of the exported telemetry artefact so the supporting evidence cannot be altered before investigation concludes.
  - Execution: dry run only; approval required; not executed
  - Status: planned (not executed)
  - Verification: Confirm a verified copy and its digest are recorded and readable.
  - Rollback: Not applicable — no rollback guidance

### 9.3 Investigation follow-up

- **confirm-account-ownership** [risk: low]
  - Purpose: Engage the account owner to determine whether they performed the new-context login and follow-on behaviours. Reviewing this evidence changes no system state.
  - Execution: dry run only; approval required; not executed
  - Status: planned (not executed)
  - Verification: Record the owner's response and whether it confirms or refutes the possible-misuse hypothesis.
  - Rollback: Not applicable — no rollback guidance

- **review-privileged-access-grant** [risk: medium]
  - Purpose: Review whether the requested privileged access was granted and whether it persists. Review alone makes no change; this is not a claim that the request succeeded.
  - Execution: dry run only; approval required; not executed
  - Status: planned (not executed)
  - Verification: Determine whether the requested role was granted and, if so, whether an independent revocation is warranted.
  - Rollback: Not applicable — no rollback guidance

- **assess-exfiltration-risk** [risk: low]
  - Purpose: Correlate the observed outbound connection and archive against egress evidence to determine whether restricted data actually left. This analyses risk; it does not assume data was exfiltrated.
  - Execution: dry run only; approval required; not executed
  - Status: planned (not executed)
  - Verification: Document definitively whether any bytes left the environment and reconcile that with the restricted-file and archive evidence.
  - Rollback: Not applicable — no rollback guidance

### 9.4 Recovery

- **require-mfa-reauthentication** [risk: medium]
  - Purpose: Require MFA re-authentication from a known device before restoring access, but only if the account is determined to have been misused. Never weaken baseline MFA requirements.
  - Execution: dry run only; approval required; not executed
  - Status: planned (not executed)
  - Verification: Confirm the account owner can re-authenticate with MFA from a verified device.
  - Rollback: After explicit review, restore the previous access policy only if doing so does not lower baseline MFA requirements.

- **rotate-account-credentials** [risk: high]
  - Purpose: Rotate the account's credentials only if misuse is established and ownership is verified. Never restore prior potentially exposed credentials.
  - Execution: dry run only; approval required; not executed
  - Status: planned (not executed)
  - Verification: Confirm the owner can authenticate with new credentials and that the prior credentials no longer work.
  - Rollback: Not applicable — no rollback guidance

## 10. Validation summary

Detection validation ran once and produced 16 cases.

| Status | Case |
|---|---|
| PASS | suspicious-corpus-unmodified |
| PASS | missing-known-good-baseline |
| PASS | missing-new-context-authentication |
| PASS | insufficient-confidence |
| PASS | correlation-window-expiry |
| PASS | wrong-actor |
| PASS | duplicate-behaviours-not-inflating |
| PASS | remove-repository-enumeration |
| PASS | remove-restricted-file-access |
| PASS | remove-privileged-access-request |
| PASS | remove-archive-creation |
| PASS | remove-network-egress |
| PASS | benign-no-finding |
| PASS | deterministic-repeatability |
| PASS | evidence-and-timeline-traceability |
| PASS | response-actions-dry-run-safe |

**Overall: passed** (16 cases)

## 11. Limitations

- This report is advisory and derived from synthetic, disposable data in an isolated lab; it is not a confirmed incident or a final incident report.
- It does not assert that an account was compromised, that data was exfiltrated, or that any impact occurred.
- Impact, exfiltration, and account state are unresolved questions, not established facts.
- Response actions are recommendations only: they are dry-run, approval-required, and were not executed.
- Validation asserts internal consistency of Duke's detection rule against its own corpus and mutations, not real-world precision or recall.
- The report timestamp is the deterministic detection timestamp (finding.created_at), not the wall-clock export time.

## 12. Conclusion

The observables are consistent with possible valid-account misuse (MITRE ATT&CK T1078) at confidence 90/100, and all 16 detection-validation cases passed. This remains an analytic assessment: account compromise, data exfiltration, and impact are not confirmed, and no response action was executed. If further investigation supports misuse, follow the approval-gated, dry-run response recommendations to preserve evidence and to contain and recover.
