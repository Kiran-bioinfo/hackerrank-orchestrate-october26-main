import csv
pred=list(csv.DictReader(open('sample_output_pred.csv')))
exp=list(csv.DictReader(open('dataset/sample_output.csv')))
mismatch=[]
for p,e in zip(pred,exp):
    if p['deletion_status']!=e['deletion_status'] or p['steps_json']!=e['steps_json']:
        mismatch.append((p['case_id'],p['deletion_status'],e['deletion_status']))
print(len(mismatch))
for m in mismatch: print(m)
