#!/usr/bin/python3
import requests
import json
import configparser
import socket
from icmplib import ping

config = configparser.ConfigParser()
config.read('config')



def request(handler):
    requests.urllib3.disable_warnings()
    url="https://{}/api/ipam/{}".format(config['PARAMS']['nb_ip'], handler)
    token=config['PARAMS']['token']
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Token {}".format(token),
 
        }
    return url, headers

def get_prefix(response):
    network = []
    for key, val in enumerate(response['results']):
        octet = (val['prefix'])
        network.append(octet)
    return network

def ip_check_create():
    ip_check_dict = {}  
    handler = 'prefixes/'
    url, headers = request(handler)
    response = requests.get(url, verify=False, headers=headers)
    response = response.json()
    network = get_prefix(response)
    for items in network:
        network = items.split('.')
        prefix = items.split('/')
        items = 1
        total = 0
        for key, val in enumerate(response['results']):
            _networkid = ('{}.{}.{}'.format( network[0], network[1], network[2]))
            print('*'*25)
            print('testing network: {}'.format(_networkid))
            while items != 254:
                hip = '{}.{}.{}.{}'.format( network[0], network[1], network[2], items)
                exists, ip_check_dict = exist_check(ip_check_dict, hip, prefix[1])
                host = ping('{}.{}.{}.{}'.format( network[0], network[1], network[2], items), count=1, interval=0.01, timeout=0.1, privileged=False)
                if host.is_alive ==  True and exists is False:
                  total = total + 1 
                  print('{}.{}.{}.{}'.format( network[0], network[1], network[2], items))
                  add_ip(hip, prefix[1])
                  #exists, ip_check_dict  = exist_check(ip_check_dict, hip, prefix[1])
                  if exists is True:
                    pass
                  elif host.is_alive == False and exists is True:
                      print('{} is dead but is in the database'.format(hip))
                  else:
                    pass  
                items = items + 1
        print('Total IPs Alive: ', total)

def tag():
  print('entering tagging function')
  handler = "ip-addresses/{}".format(ipid)
  url, headers = request(handler)
  ipdict = {"address": "{}/{}".format(hip, prefix)}
  response = requests.post(url, json=ipdict, verify=False, headers=headers)
  print(response)

def add_ip(hip, prefix):
  print('entering add IP function')
  a = input('adding IP')
  handler = "ip-addresses/"
  url, headers = request(handler)
 # a = input('adding IP')
  ipdict = {"address": "{}/{}".format(hip, prefix)}
  response = requests.post(url, json=ipdict, verify=False, headers=headers)
  print(response)
  #a = input('pausing')


def exist_check(ip_check_dict, hip, prefix):
  #print('entering IP checking function')
  handler = 'ip-addresses/?limit=5000'
  if not ip_check_dict:
    url, headers = request(handler)
    a = input('making API call')
    response = requests.get(url, verify=False, headers=headers)
    ip_check_dict = response.json()
  for key, val in enumerate(ip_check_dict['results']):
    _network = val["display"].split("/")
    #if hip == _network[0]:
    #  ipid = (val['id'])
    #print(hip, _network[0])
    if _network[0] == hip:
      print('ip exists, skipping')
      return True, ip_check_dict
    else:
      pass
  return False, ip_check_dict
    


ip_check_create()
