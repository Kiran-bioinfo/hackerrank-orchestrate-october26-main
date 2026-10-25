import sys

path = r"C:\Users\MSI\Desktop\hackerrank-orchestrate-october26-main\code\utils.py"
with open(path, encoding="utf-8") as f:
    s = f.read()

# Improve lookup_activity_events
old_lookup = '''def lookup_activity_events(
    resource_id: str,
    audit_at_dt: datetime,
    activity_df: "pd.DataFrame",
) -> list[dict[str, Any]]:
    """Return system_activity.csv events for *resource_id* at or before *audit_at_dt*.

    Each event dict: {activity_id, event_time, event_type, source_system,
    target_system, reported_result, details}.
    """
    if activity_df is None or activity_df.empty or not resource_id:
        return []

    mask = activity_df["resource_id"] == resource_id
    if not mask.any():
        return []

    subset = activity_df[mask].copy()
    # Filter to events at or before audit_at
    if "event_time_dt" in subset.columns:
        subset = subset[subset["event_time_dt"] <= audit_at_dt]

    events: list[dict[str, Any]] = []
    for _, row in subset.iterrows():
        events.append({
            "activity_id": row.get("activity_id", ""),
            "event_time": row.get("event_time", ""),
            "event_type": row.get("event_type", ""),
            "source_system": row.get("source_system", ""),
            "target_system": row.get("target_system", ""),
            "reported_result": row.get("reported_result", ""),
            "details": row.get("details", ""),
        })
    return events'''

new_lookup = '''def lookup_activity_events(
    resource_id: str,
    audit_at_dt: datetime,
    activity_df: "pd.DataFrame",
    aliases: dict[str, set[str]] | None = None,
) -> list[dict[str, Any]]:
    """Return system_activity.csv events for *resource_id* at or before *audit_at_dt*.

    Also matches events where details contains any alias email/user_id if
    aliases are provided. Each event dict: {activity_id, event_time, event_type,
    source_system, target_system, reported_result, details, resource_id}.
    """
    if activity_df is None or activity_df.empty:
        return []

    emails_l = set()
    user_ids_s = set()
    if aliases:
        emails_l = {str(e).lower() for e in (aliases.get("emails") or set()) if e}
        user_ids_s = {str(u).strip() for u in (aliases.get("user_ids") or set()) if u}

    mask = pd.Series([False] * len(activity_df), index=activity_df.index)
    if resource_id:
        mask = mask | (activity_df["resource_id"].astype(str) == str(resource_id))

    # Also match by aliases in details or resource_id
    if aliases:
        for idx, row in activity_df.iterrows():
            if mask.at[idx]:
                continue
            details = str(row.get("details", ""))
            rid = str(row.get("resource_id", ""))
            dl = details.lower()
            matched = False
            for em in emails_l:
                if em and em in dl:
                    matched = True
                    break
            if not matched:
                for uid in user_ids_s:
                    if uid and (uid in rid or uid.lower() in dl):
                        matched = True
                        break
            if matched:
                mask.at[idx] = True

    if not mask.any():
        return []

    subset = activity_df[mask].copy()
    # Filter to events at or before audit_at
    if "event_time_dt" in subset.columns and audit_at_dt is not None:
        subset = subset[subset["event_time_dt"] <= audit_at_dt]

    events: list[dict[str, Any]] = []
    for _, row in subset.iterrows():
        events.append({
            "activity_id": row.get("activity_id", ""),
            "event_time": row.get("event_time", ""),
            "event_type": row.get("event_type", ""),
            "source_system": row.get("source_system", ""),
            "target_system": row.get("target_system", ""),
            "reported_result": row.get("reported_result", ""),
            "details": row.get("details", ""),
            "resource_id": row.get("resource_id", ""),
        })
    return events'''

if old_lookup not in s:
    print("lookup not found")
    sys.exit()
s = s.replace(old_lookup, new_lookup)

# Append new functions
append = r'''


# ---------------------------------------------------------------------------
# 6. Replication / Active Flow Scanning
# ---------------------------------------------------------------------------


def scan_activity_for_user_aliases(
    aliases: dict[str, set[str]],
    audit_at_dt: datetime,
    activity_df: "pd.DataFrame",
) -> list[dict[str, Any]]:
    """Find system_activity events (any event_type) whose details or resource_id
    contains any alias email/user_id/phone, at or before audit_at.
    """
    if activity_df is None or activity_df.empty or not aliases:
        return []

    emails = set(aliases.get("emails", set()) or set())
    user_ids = set(aliases.get("user_ids", set()) or set())
    phones = set(aliases.get("phones", set()) or set())

    emails_l = {str(e).lower() for e in emails if e}
    user_ids_s = {str(u).strip() for u in user_ids if u}
    phones_s = {str(p).strip() for p in phones if p}

    events: list[dict[str, Any]] = []
    for _, row in activity_df.iterrows():
        # Check time
        if "event_time_dt" in activity_df.columns and audit_at_dt is not None:
            et = row.get("event_time_dt")
            try:
                if pd.notna(et) and et > audit_at_dt:
                    continue
            except Exception:
                pass

        details = str(row.get("details", ""))
        rid = str(row.get("resource_id", ""))
        dl = details.lower()

        matched = False
        for em in emails_l:
            if em and em in dl:
                matched = True
                break
        if not matched:
            for uid in user_ids_s:
                if uid and (uid in rid or uid.lower() in dl):
                    matched = True
                    break
        if not matched:
            for ph in phones_s:
                if ph and ph in details:
                    matched = True
                    break

        if matched:
            events.append({
                "activity_id": row.get("activity_id", ""),
                "event_time": row.get("event_time", ""),
                "event_type": row.get("event_type", ""),
                "source_system": row.get("source_system", ""),
                "target_system": row.get("target_system", ""),
                "reported_result": row.get("reported_result", ""),
                "details": row.get("details", ""),
                "resource_id": row.get("resource_id", ""),
            })
    return events


def detect_active_replication_flows(
    resource_id: str,
    audit_at_dt: datetime,
    activity_df: "pd.DataFrame",
    aliases: dict[str, set[str]] | None = None,
) -> list[dict[str, Any]]:
    """Scan system_activity.csv for events where event_type contains "SYNC",
    "REPLICATE", "RESTORE", "AUTO_RESTORE", "IMPORT" and the details or
    resource_id match the user's aliases/resource, at or before audit_at.
    """
    if activity_df is None or activity_df.empty:
        return []

    keywords = ("sync", "replicate", "restore", "auto_restore", "import")

    # Get candidate events
    candidates = []
    if resource_id:
        candidates = lookup_activity_events(resource_id, audit_at_dt, activity_df, aliases)
    if not candidates and aliases:
        candidates = scan_activity_for_user_aliases(aliases, audit_at_dt, activity_df)

    results: list[dict[str, Any]] = []
    for ev in candidates:
        etype = str(ev.get("event_type", "")).lower()
        if any(k in etype for k in keywords):
            results.append(ev)
            continue
        # Also check details
        details = str(ev.get("details", "")).lower()
        if any(k in details for k in keywords):
            results.append(ev)
            continue
    return results

'''

with open(path, "w", encoding="utf-8") as f:
    f.write(s + append)
print("done")
