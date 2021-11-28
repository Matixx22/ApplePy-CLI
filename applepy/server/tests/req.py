import requests

url = 'http://127.0.0.1:8000/'

# GET /network-config
# r = requests.get(url + 'network-config')

# POST /packet-capture
# r = requests.post(url + 'packet-capture', json={
#     'count': 50,
#     'iface': 'ens33',
#     'filter': ''
# })

# POST /cmd
r = requests.post(url + 'cmd', json={
    'cmd': 'ls',
    'args': '-l ../..'
})


print(r.json())