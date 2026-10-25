# Evaluation Report

## Architecture Summary (Pipeline Phases)

The solution is a deterministic, rule-based deletion-audit agent. It processes every request in `dataset/deletion_requests.csv` through the following phases:

1. **Authorization (FINDING phase gate):** Parse `request_text` to determine whether the request authorizes deletion. Non-deletion requests (access, correction, export, marketing opt-out, etc.) are classified as `NOT_APPLICABLE` with `steps_json=[]`.
2. **Identity Resolution:** Resolve the subject from the supplied email against `user_identities.csv` (current snapshot) and `user_audit_log.csv` (historical changes) to reconstruct both current and historical identifiers (name, email, phone, email hash, stable `user_id`).
3. **Evidence Gathering:** Walk `evidence_files.csv` and inspect participant-visible evidence (PDFs, screenshots, logs, JSON, text records, SQL snapshots) to locate records tied to the subject via identifiers, hashes, resource IDs, system IDs, and timestamps. Evidence captured after `audit_at` is excluded.
4. **Rule Application:** Apply `deletion_rules.csv` to every relevant record — whole-record deletion, redaction of prohibited identifiers, anonymization, retention, or preservation of an account tombstone (stable internal user reference retained, direct identifiers removed).
5. **State Reconstruction:** Determine true state at `audit_at` from evidence, ignoring `reported_status`/workflow claims. Detect active data flows (sync, import, restore) and restore risks (backups).
6. **Decision:** `COMPLETE` only if every relevant copy has required treatment, required retained records remain, and no active recreation path exists; otherwise `INCOMPLETE`.
7. **Output Serialization:** Emit ordered steps (FINDING -> REMEDIATION -> VERIFICATION), numbered consecutively, with evidence IDs for findings/COMPLETE verification and empty evidence IDs for future remediation/verification steps. Sort rows by `case_id`.

## Sample Benchmark

Evaluated against `dataset/sample_deletion_requests.csv` / `dataset/sample_output.csv` (32 public requests):

- Deletion-status accuracy: **26/32 = 81.2%**
- Step count: 102 predicted vs 193 expected (recall gap concentrated in multi-record cases requiring deeper evidence traversal)

## Custom Evaluation Cases

### Case A - Transitive Aliases

A subject requests deletion under a historical email that appears only in `user_audit_log.csv`. The current snapshot uses a different email, but older systems and support attachments still reference the historical email and its hash. The agent must traverse the audit trail to recover the alias, then match evidence across systems using the historical identifier. Failure mode: stopping at the current snapshot misses records keyed to the historical alias.

### Case B - Unscrubbed Replica

A primary record is reported deleted by the workflow, but a regional reporting replica still contains the subject's email and phone (replication drift). The agent must compare SQL snapshot tables across replicas and flag the replica row as `REPORT_REMAINING_RECORD` (PRESENT), with remediation `DELETE_RECORD` and verification `VERIFY_RECORD_ABSENT`. Failure mode: trusting the workflow's `COMPLETE` status.

### Case C - Compliant Tombstone

An account is deleted but the policy requires an `ACCOUNT_TOMBSTONE` retaining the stable `user_id` while removing name, email, phone, email hash, and other direct identifiers. The agent must classify this as `COMPLETE` (not incomplete) and emit `VERIFY_RECORD_PRESENT`/`VERIFY_RECORD_REDACTED` steps citing evidence. Failure mode: treating any retained identifier as a violation.

## Failures Found and Improvements Made

- **Over-trusting reported status:** Initial logic accepted workflow `COMPLETE` claims; fixed by requiring evidence-backed state reconstruction at `audit_at`.
- **Alias resolution gap:** Early pass only matched current snapshot email; fixed by incorporating `user_audit_log.csv` historical changes to recover transitive identifiers.
- **Replica oversight:** Single-source checks missed regional/reporting replicas; fixed by comparing all SQL snapshot tables and snapshot times.
- **Tombstone misclassification:** Retained stable `user_id` was flagged as residual PII; fixed by distinguishing permitted stable references from prohibited direct identifiers per `REDACT` rules.
- **Evidence timing:** Late-captured evidence initially influenced answers; fixed by enforcing `audit_at` cutoff.
- **Step ordering:** Remediation now disables data flows and blocks restores before modifying dependent records, and processes downstream copies before sources where required.
- **Serialization:** Ensured valid JSON array, consecutive step numbering, and phase ordering FINDING -> REMEDIATION -> VERIFICATION.
