import requests

url = 'http://127.0.0.1:8000/'

# GET /network-config
# r = requests.get(url + 'network-config')

# POST /packet-capture
r = requests.post(url + 'packet-capture', json={
    'count': 10,
    'iface': 'ens33',
    'filter': 'tcp'
})

print(r.text)
