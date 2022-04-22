import requests
import json
import configparser
from icmplib import ping

config = configparser.ConfigParser()
config.read('config')

url="https://{}/api/ipam/ip-addresses/?limit=5000".format(config['PARAMS']['nb_ip'])
token=config['PARAMS']['token']
headers = {
    "Content-Type": "application/json",
    "Authorization": "Token {}".format(token),
 
}
response = requests.get(url, verify=False, headers=headers)
responsep = response.json()

for index, key in enumerate(responsep["results"]):
  ip=responsep["results"][index]["address"].split("/")
  host = ping(ip[0], count=1, interval=0.01, timeout=0.1, privileged=False)
  if host.is_alive == True:
    print("host {} is alive" .format(ip[0]))
  else:
    pass
