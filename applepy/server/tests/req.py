import requests
import wget

url = 'http://127.0.0.1:8000/'

# GET /network-config
# r = requests.get(url + 'network-config')

# POST /packet-capture
# r = requests.post(url + 'packet-capture', json={
#     'count': 10,
#     'iface': 'eth0',
#     'filter': 'tcp'
# })

# GET /pcaps
# r = requests.get(url + 'pcaps')

# GET /pcaps/<id>
# wget.download(url + 'pcaps/2')

# GET /logs
# r = requests.get(url + 'logs')

# GET /logs/<id>
# wget.download(url + 'logs/53')

# POST /cmd
r = requests.post(url + 'cmd', json={
    'cmd': 'ls',
    'args': '-l ../..'
})


print(r.json())
