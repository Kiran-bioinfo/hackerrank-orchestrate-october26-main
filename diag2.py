import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent / "code"))
import pandas as pd
from main import apply_policy, gather_evidence
from utils import (DATASET_DIR, load_deletion_requests, load_user_identities, load_user_audit_log,
    load_evidence_files, load_system_activity, load_deletion_rules, find_user_by_email)
from classifier import classify_intent

sample_out = pd.read_csv("dataset/sample_output.csv")
expected_map = dict(zip(sample_out["case_id"], sample_out["deletion_status"]))
reqs = load_deletion_requests(sample=True)
identities = load_user_identities()
audit_log = load_user_audit_log()
evidence_df = load_evidence_files()
activity_df = load_system_activity()
rules_df = load_deletion_rules()

target = ["case_09","case_10","case_12","case_14","case_15","case_19"]
lines = []
for cid in target:
    row = reqs[reqs["case_id"]==cid].iloc[0]
    email = row["email"]
    audit_at = row["audit_at"]
    audit_at_dt = pd.to_datetime(audit_at)
    user_id, aliases = find_user_by_email(email, identities, audit_log)
    emails = aliases.get("emails", set())
    phones = aliases.get("phones", set())
    ev_records = gather_evidence(aliases, audit_at_dt, evidence_df, activity_df, DATASET_DIR)
    policy = apply_policy(ev_records, rules_df, aliases)
    intent = classify_intent(row["request_text"])
    pred_df = pd.read_csv("sample_output_pred.csv")
    pred = pred_df[pred_df["case_id"]==cid]["deletion_status"].iloc[0]
    exp = expected_map[cid]
    lines.append("=== " + cid + " ===")
    lines.append("request_text: " + str(row["request_text"]))
    lines.append("predicted: " + str(pred) + "  expected: " + str(exp))
    lines.append("classify_intent: " + str(intent))
    lines.append("audit_at: " + str(audit_at))
    lines.append("aliases: user_id=" + str(user_id) + " emails=" + str(sorted(emails)) + " phones=" + str(sorted(phones)))
    lines.append("matched evidence:")
    for p in policy:
        lines.append("  resource_id=" + str(p.get("resource_id")) + " system_id=" + str(p.get("system_id")) + " category=" + str(p.get("category")) +
                     " actual_state=" + str(p.get("actual_state")) + " exposed_pii=" + str(p.get("exposed_pii")) +
                     " is_violation=" + str(p.get("is_violation")) + " is_compliant=" + str(p.get("is_compliant")) +
                     " evidence_id=" + str(p.get("evidence_id")) + " _captured_at=" + str(p.get("_captured_at")))
    lines.append("")

text = "\n".join(lines)
Path("diagnostic_remaining.txt").write_text(text, encoding="utf-8")
print(text)
