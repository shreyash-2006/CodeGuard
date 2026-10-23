import sys, json; sys.path.insert(0,'d:/hackathon')
from codeguard.engine import analyze
from codeguard.ml_model import ensure_model_ready

model = ensure_model_ready(dev_path='codeguard_dev.jsonl')
lines = open('codeguard_dev.jsonl').readlines()

# Find secret_access FP and resource_exhaustion FN items
for i, line in enumerate(lines):
    obj = json.loads(line)
    code = obj['code']
    cat = obj.get('category','benign')
    result = analyze(code, model)
    pred_cats = set(result.get('categories',[]))
    gold_cats = set(c.strip() for c in cat.split(',') if c.strip() not in ('benign',))
    
    if 'secret_access' in pred_cats and 'secret_access' not in gold_cats:
        print(f'[secret_access FP] {obj["id"]}')
        print(f'  gold={sorted(gold_cats)} pred={sorted(pred_cats)}')
        print(f'  risk={result["risk_score"]}')
    if 'resource_exhaustion' not in pred_cats and 'resource_exhaustion' in gold_cats:
        print(f'[resource_exhaustion FN] {obj["id"]}')
        print(f'  gold={sorted(gold_cats)} pred={sorted(pred_cats)}')
    if 'yaml' in obj.get('language',''):
        print(f'[yaml] {obj["id"]} pred_lang={result["code_language"]}')
        print(f'  code[:100]={repr(code[:100])}')
