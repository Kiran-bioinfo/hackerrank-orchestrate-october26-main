import csv, json

def load_csv(path):
    with open(path, newline='', encoding='utf-8') as f:
        return {r['case_id']: r for r in csv.DictReader(f)}

pred = load_csv('output.csv')
gold = load_csv('dataset/sample_output.csv')

for cid in ['case_03','case_09','case_11','case_13','case_15','case_23','case_24','case_29','case_30','case_31']:
    g = gold[cid]
    p = pred.get(cid, {})
    g_steps = json.loads(g['steps_json']) if g['steps_json'] else []
    p_steps = json.loads(p['steps_json']) if p['steps_json'] else []
    print(f'=== {cid} === gold={g["deletion_status"]} pred={p["deletion_status"]}')
    print(f'  Gold steps ({len(g_steps)}):')
    for s in g_steps[:5]:
        print(f'    {s["phase"]} {s["operation"]} {s["resource_id"]} ev={s["evidence_id"]}')
    if len(g_steps) > 5:
        print(f'    ... ({len(g_steps)} total)')
    print(f'  Pred steps ({len(p_steps)}):')
    for s in p_steps[:5]:
        print(f'    {s["phase"]} {s["operation"]} {s["resource_id"]} ev={s["evidence_id"]}')
    if len(p_steps) > 5:
        print(f'    ... ({len(p_steps)} total)')
    print()
