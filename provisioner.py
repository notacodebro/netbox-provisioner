#!/usr/bin/python3
from cgitb import handler
import requests
import json
import configparser
import socket
from icmplib import ping

config = configparser.ConfigParser()
config.read('config')



def request(handler):
    url="https://{}/api/ipam/{}".format(config['PARAMS']['nb_ip'], handler)
    token=config['PARAMS']['token']
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Token {}".format(token),
 
        }
    response = requests.get(url, verify=False, headers=headers)
    return response.json()

def get_prefix(responsep):
    network = []
    for key, val in enumerate(responsep['results']):
        octet = (val['prefix'])
        network.append(octet)
    return network

def ip_check_create():
    handler = 'prefixes/'
    responsep = request(handler)
    network = get_prefix(responsep)
    for items in network:
        network = items.split('.')
        items = 1
        total = 0
        for key, val in enumerate(responsep['results']):
            _networkid = ('{}.{}.{}'.format( network[0], network[1], network[2]))
            print('*'*25)
            print('testing network: {}'.format(_networkid))
            while items != 254:
                hip = '{}.{}.{}.{}'.format( network[0], network[1], network[2], items)
                host = ping('{}.{}.{}.{}'.format( network[0], network[1], network[2], items), count=1, interval=0.01, timeout=0.1, privileged=False)
                if host.is_alive ==  True:
                    print('{}.{}.{}.{}'.format( network[0], network[1], network[2], items))
                    total = total + 1 
                    print('IP exists: ', hip)
                else:
                    pass
                items = items + 1
        print('Total IPs Alive: ', total)

def add_ip():
  handler = 'ip-addresses/?limit=5000'
  responsep = request(handler)

  pass
def exist_check(hip):
    a = input('exist')
    handler = 'ip-addresses/?limit=5000'
    responsep = request(handler)
    a = input('exist')
    for index, key in enumerate(responsep["results"]):
        ip=responsep["results"][index]["address"].split("/")
        print(ip[0], hip)
        a = input('exist')
        a = input('exist')
        if ip[0] == hip:
            print('exists!')
        else:
            pass
    
ip_check_create()
