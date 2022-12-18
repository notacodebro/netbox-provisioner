#!/usr/bin/python3
import requests
import json
import configparser
import socket
from icmplib import ping
import time
import ipaddress
import argparse

config = configparser.ConfigParser()
config.read('config')

def request(handler): 
    """ This request funuction accepts handler as its passed parameter and
    should contain the resource location to build the URL.

    The returned data is the composed URL and header which includes the
    authentication token. """
    requests.urllib3.disable_warnings()
    url = f"https://{config['PARAMS']['nb_ip']}/api/ipam/{handler}"
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
    """ this function is not working. The intent is to set tags based on ICMP status
    to preserve the IP allocation when a host is down/offline and not decomissioned"""
    _tag = 'ip-down' 
    print('entering tagging function')
    handler = f"ip-addresses/{ipid}/"
    url, headers = request(handler)
    print(ipid)
    ipdict = {"tags": "['{_tag}']"}
    response = requests.patch(url, json=ipdict, verify=False, headers=headers)

def add_ip(hip, prefix):
    handler = "ip-addresses/"
    url, headers = request(handler)
    ipdict = {"address": "{}/{}".format(hip, prefix)}
    response = requests.post(url, json=ipdict, verify=False, headers=headers)
    print(f'new IP address added: {hip}')

def dns_update(hip, ipid):
    handler = "ip-addresses/{}/".format(ipid)
    url, headers = request(handler)
    try:
        dns_name = socket.gethostbyaddr(hip)
        #print(dns_name[0])
        dnsdict = {"dns_name": "{}".format(dns_name[0])}
        response = requests.patch(url, json=dnsdict, verify=False, headers=headers)
        print(f'adding dns record for {hip}')
    except:
        print(f'PRT record missing for {hip}. Please check zone')

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
            #dns_update(hip, ipid)
            return True, ip_check_dict, ipid
        else:
            pass
    return False, ip_check_dict, ipid

def ip_check(hip):
    return ping(hip, count=1, interval=0.01, timeout=0.1, privileged=False)

def ip_check_create(arg_network = ''):
    ip_check_dict = {}  
    _network = []
    handler = 'prefixes/'
    url, headers = request(handler)
    response = requests.get(url, verify=False, headers=headers)
    response = response.json()
    if arg_network: _network.append(arg_network)
    else:
        _network = get_prefix(response)
    for items in _network:
        _netid = ipaddress.ip_network(items)
        prefix = (str(_netid).split('/')[1])
        _total = 0
        print('*'*25)
        print(f'testing network: {_netid}')
        start = time.clock_gettime(0)
        for nets in _netid.hosts():
            hip = str(nets)
            exists, ip_check_dict, ipid = exist_check(ip_check_dict, hip)
            host = ip_check(hip)
            if exists is True: 
                _total = _total + 1
            if host.is_alive ==  True and exists is False:
                add_ip(hip, prefix)
            elif host.is_alive == False and exists is True:
                print(f'{hip} is offline but is in the database')
                #set_tag(ipid)
            else:
                pass  
        print(f'Total IPs active and in the database: {_total}')
        end = time.clock_gettime(0)
        print(f'it took {round(end - start)} seconds to complete the last function')
    
def arg_input():
    _parser = argparse.ArgumentParser()
    _parser.add_argument('--network', help='define network to run provisioner agains', required=False, action='store')
    args=_parser.parse_args()

    if args.network: ip_check_create(args.network)

    else: ip_check_create()

if __name__ == '__main__': arg_input()
