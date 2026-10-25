import sys; sys.path.insert(0,'code')
from utils import load_evidence_file, load_evidence_files

ev_df = load_evidence_files()
row = ev_df[ev_df['file_id'] == 'evidence_03'].iloc[0]
print('File path:', row['file_path'])
print('Captured at:', row['captured_at'])

records = load_evidence_file(row)
print(f'Records: {len(records)}')
for r in records[:10]:
    rj = r.get('record_json', {})
    print(f'  {r["resource_id"]} | {r["origin_system"]} | email={rj.get("email","N/A")} | state={r.get("actual_state_override","N/A")}')
