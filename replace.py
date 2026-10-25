import sys

path = r"C:\Users\MSI\Desktop\hackerrank-orchestrate-october26-main\code\utils.py"
with open(path, encoding="utf-8") as f:
    s = f.read()

start = s.find("def record_matches_aliases")
if start == -1:
    print("not found")
    sys.exit()
end = s.find("\n\ndef ", start + 1)
if end == -1:
    end = len(s)

newfunc = """def record_matches_aliases(record: dict[str, Any], aliases: dict[str, set[str]]) -> bool:
    \"\"\"Return True if any identifier in *record* matches the user's aliases.

    Broadly scans ALL nested values (recursive, depth up to 4) and also checks
    resource_id substrings and system_activity details. Also checks if any
    alias appears as a substring in any string value.
    \"\"\"
    rj = record.get("record_json", {}) or {}

    emails = set(aliases.get("emails", set()) or set())
    email_hashes = set(aliases.get("email_hashes", set()) or set())
    user_ids = set(aliases.get("user_ids", set()) or set())
    phones = set(aliases.get("phones", set()) or set())

    emails_l = {str(e).lower() for e in emails if e}
    email_hashes_l = {str(e).lower() for e in email_hashes if e}
    phones_s = {str(p).strip() for p in phones if p}
    user_ids_s = {str(u).strip() for u in user_ids if u}

    def _check_exact(val: Any) -> bool:
        if val is None or val == "":
            return False
        v = str(val).strip()
        if not v:
            return False
        vl = v.lower()
        if v in user_ids_s or vl in emails_l or vl in email_hashes_l or v in phones_s:
            return True
        return False

    def _check_substring_in_str(s: str) -> bool:
        if not s:
            return False
        sl = s.lower()
        for em in emails_l:
            if em and em in sl:
                return True
        for eh in email_hashes_l:
            if eh and eh in sl:
                return True
        for uid in user_ids_s:
            if not uid:
                continue
            if uid in s or uid.lower() in sl:
                return True
        for ph in phones_s:
            if ph and ph in s:
                return True
        return False

    def _check_value(val: Any) -> bool:
        if val is None or val == "":
            return False
        if isinstance(val, (str, int, float, bool)):
            s = str(val)
            if _check_exact(s):
                return True
            if _check_substring_in_str(s):
                return True
            return False
        return False

    def _scan_recursive(obj: Any, depth: int = 0) -> bool:
        if depth > 4:
            return False
        if obj is None or obj == "":
            return False
        if isinstance(obj, (str, int, float, bool)):
            return _check_value(obj)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(k, str):
                    kl = k.lower()
                    if kl in ("user_id", "customer_reference", "subject_reference",
                              "email", "email_hash", "phone", "customer_email",
                              "lookup_key", "subject_selector", "resource_id",
                              "details", "message", "body", "text", "event_details", "raw_line"):
                        if _check_value(v):
                            return True
                if _check_value(v):
                    return True
                if _scan_recursive(v, depth + 1):
                    return True
            return False
        elif isinstance(obj, list):
            for item in obj:
                if _check_value(item):
                    return True
                if _scan_recursive(item, depth + 1):
                    return True
            return False
        else:
            return _check_value(obj)

    for key in ("user_id", "customer_reference", "subject_reference",
                "email", "email_hash", "phone",
                "customer_email", "lookup_key", "subject_selector",
                "resource_id"):
        if _check_value(record.get(key)):
            return True

    if _scan_recursive(rj, 0):
        return True

    raw = record.get("raw_line", "")
    if raw and _check_substring_in_str(str(raw)):
        return True
    for key in ("details", "message", "body", "text", "raw_data", "event_details"):
        val = record.get(key)
        if isinstance(val, str) and _check_substring_in_str(val):
            return True
        elif val is not None and _scan_recursive(val, 0):
            return True

    return False


"""

s2 = s[:start] + newfunc + s[end:]
with open(path, "w", encoding="utf-8") as f:
    f.write(s2)
print("done")
