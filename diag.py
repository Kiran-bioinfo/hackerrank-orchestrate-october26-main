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

target = ["case_03","case_09","case_21","case_25","case_26","case_27","case_28","case_31"]
lines = []
for cid in target:
    row = reqs[reqs["case_id"]==cid].iloc[0]
    email = row["email"]
    audit_at = row["audit_at"]
    audit_at_dt = pd.to_datetime(audit_at)
    user_id, aliases = find_user_by_email(email, identities, audit_log)
    emails = aliases.get("emails", set())
    ev_records = gather_evidence(aliases, audit_at_dt, evidence_df, activity_df, DATASET_DIR)
    policy = apply_policy(ev_records, rules_df, aliases)
    intent = classify_intent(row["request_text"])
    out = pd.read_csv("output.csv")
    pred = out[out["case_id"]==cid]["deletion_status"].iloc[0]
    exp = expected_map[cid]
    lines.append("=== " + cid + " ===")
    lines.append("request_text: " + str(row["request_text"])[:120])
    lines.append("predicted: " + str(pred) + "  expected: " + str(exp))
    lines.append("user_id: " + str(user_id) + "  emails: " + str(sorted(emails)))
    lines.append("intent: " + str(intent))
    lines.append("evidence records:")
    for p in policy:
        lines.append("  resource_id=" + str(p["resource_id"]) + " system_id=" + str(p["system_id"]) + " category=" + str(p["category"]) +
                     " actual_state=" + str(p["actual_state"]) + " exposed_pii=" + str(p["exposed_pii"]) +
                     " is_violation=" + str(p["is_violation"]) + " is_compliant=" + str(p["is_compliant"]) + " evidence_id=" + str(p["evidence_id"]))
    lines.append("")

text = "\n".join(lines)
Path("diagnostic_out.txt").write_text(text, encoding="utf-8")
print(text)
