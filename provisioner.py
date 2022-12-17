#!/usr/bin/python3
import requests
import json
import configparser
import socket
from icmplib import ping
import time
import ipaddress

config = configparser.ConfigParser()
config.read('config')

def request(handler): 
    """ This request funuction accepts handler as its passed parameter and
    should contain the resource location to build the URL.

    The returned data is the composed URL and header which includes the
    authentication token. """
    requests.urllib3.disable_warnings()
    url="https://{}/api/ipam/{}".format(config['PARAMS']['nb_ip'], handler)
    token=config['PARAMS']['token']
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Token {}".format(token),
 
        }
    return url, headers

def get_prefix(response):
    """ This get prefix function accepts """ 
    network = []
    for key, val in enumerate(response['results']):
        octet = (val['prefix'])
        network.append(octet)
    return network

def set_tag(ipid):
    tag = 'ip-down' 
    print('entering tagging function')
    handler = "ip-addresses/{}/".format(ipid)
    url, headers = request(handler)
    print(ipid)
    ipdict = {"tags": "['{}']".format(tag)}
    response = requests.patch(url, json=ipdict, verify=False, headers=headers)
    print(response)

def add_ip(hip, prefix):
    handler = "ip-addresses/"
    url, headers = request(handler)
    ipdict = {"address": "{}/{}".format(hip, prefix)}
    response = requests.post(url, json=ipdict, verify=False, headers=headers)
    print(response)
    blah = input("added IP:".format(hip))

def dns_update(hip, ipid):
    handler = "ip-addresses/{}/".format(ipid)
    url, headers = request(handler)
    try:
        dns_name = socket.gethostbyaddr(hip)
        print(dns_name[0])
        dnsdict = {"dns_name": "{}".format(dns_name[0])}
        response = requests.patch(url, json=dnsdict, verify=False, headers=headers)
        print('adding dns record for {}'.format(hip))
    except:
        print('PRT record missing for {}. Please check zone'.format(hip))

def exist_check(ip_check_dict, hip):
    ipid = 0
    handler = 'ip-addresses/?limit=5000'
    if not ip_check_dict:
        url, headers = request(handler)
        response = requests.get(url, verify=False, headers=headers)
        ip_check_dict = response.json()
    for key, val in enumerate(ip_check_dict['results']):
        _network = val["display"].split("/")
        ipid = val['id']
        if _network[0] == hip:
            dns_update(hip, ipid)
            return True, ip_check_dict, ipid
        else:
            pass
    return False, ip_check_dict, ipid

def ip_check(hip):
    return ping(hip, count=1, interval=0.01, timeout=0.1, privileged=False)

def ip_check_create():
    ip_check_dict = {}  
    handler = 'prefixes/'
    url, headers = request(handler)
    response = requests.get(url, verify=False, headers=headers)
    response = response.json()
    network = get_prefix(response)
    for items in network:
        #networkid = items.split('.')
        #network = "{}.{}.{}.".format(networkid[0], networkid[1], networkid[2])
        netnet = ipaddress.ip_network(items)
        #print(type(netnet))
        prefix = (str(netnet).split('/')[1])
        print(prefix)
        blah = input('hit a key')
        #sortednet = items.split('/')
        #items = 1
        total = 0
        print('*'*25)
        print('testing network: {}'.format(netnet))
        for nets in netnet.hosts():
            hip = str(nets)
            print(hip)
            exists, ip_check_dict, ipid = exist_check(ip_check_dict, hip)
            host = ip_check(hip)
            if exists is True:
                total = total + 1
            if host.is_alive ==  True and exists is False:
                add_ip(hip, prefix)
            elif host.is_alive == False and exists is True:
                print('{} is offline but is in the database'.format(hip))
                set_tag(ipid)
            else:
                pass  
            #items = items + 1
        print('Total IPs active and in the database: {}'.format(total))

    
ip_check_create()
ts = time.time()
print(ts)
