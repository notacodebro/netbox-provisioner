#!/usr/bin/python3 
import requests
import json
import configparser
import socket
import time
import ipaddress
import argparse
import progressbar
from icmplib import ping
from tabulate import tabulate

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
    """ This get prefix function accepts the response JSON object from the prefix endpoint and
    return the network ID for each index in the list""" 
    network = []
    for key, val in enumerate(response['results']):
        octet = (val['prefix'])
        network.append(octet)
    return network

def set_tag(ipid):
    """ This function is not working. The intent is to set tags based on ICMP status
    to preserve the IP allocation when a host is down/offline and not decomissioned"""
    _tag = 'ip-down' 
    print('entering tagging function')
    handler = f"ip-addresses/{ipid}/"
    url, headers = request(handler)
    print(ipid)
    ipdict = {"tags": "['{_tag}']"}
    response = requests.patch(url, json=ipdict, verify=False, headers=headers)

def add_ip(hip, prefix):
    """ The add IP function does exactly what it says, it adds IPs irrespective of database 
    presense, which is checked in a different function. A print is confirmed within the function rather
    than a return and mapped status 
    
    this function recieves provided or enumerated IP addresses and the network prefix
    """

    handler = "ip-addresses/"
    url, headers = request(handler)
    ipdict = {"address": "{}/{}".format(hip, prefix)}
    response = requests.post(url, json=ipdict, verify=False, headers=headers)
    print(f'new IP address added: {hip}')

def dns_update(hip, ipid):
    """ This function will update the DNS record for each IP address. It will perform the update
    irrespective of an existence check(to be upated)

    this function recieves provided or enumerated IP addresses and the ip address identifier provided by the netbox endpoint"""
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
    """ This function checks the existing of each IP address in the network range to ensre
    that IP addresses are not continually re-added or overwritten.

    This funtion recieves individual IPs through hip and the the ip_check_dict for id parsing"""  
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
    """ This function performs ICMP checking for ip/host existence. It recieved the provided or enumerated
    IP range/host """
    return ping(hip, count=1, interval=0.06, timeout=0.1, privileged=False)

def ip_check_create(arg_network = ''):
    """ This function provides the intial triage and direction of the provisioner. the default parameter is blank to 
    account for no argument provided by the user. The function will initially poll the prefixes endpoint and recieve a 
    list of network's that are *required* to be pre-populated or user defined through the call of the script. 
    """
    ip_check_dict = {}  
    _network = []
    _offline_hosts = []
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
        bar = progressbar.ProgressBar(max_value=30, max_error=False, poll_interval=.1)
        print('\n')
        for nets in _netid.hosts():
            hip = str(nets)
            exists, ip_check_dict, ipid = exist_check(ip_check_dict, hip)
            host = ip_check(hip)
            if exists is True: 
                _total = _total + 1
            if host.is_alive ==  True and exists is False:
                add_ip(hip, prefix)
            elif host.is_alive == False and exists is True:
                _offline_hosts.append(hip)
                #set_tag(ipid)
            else:
                pass  
            bar.update(_total)
        end = time.clock_gettime(0)
        table = [['Online IPs', _total], ['Offlne IPs', _offline_hosts], ['Completed', f'{round(end - start)} seconds',]]
        print(tabulate(table, tablefmt="grid", maxcolwidths=[None, 21]))
def arg_input():
    """ Argument parse function to accept spcific network range from user input. This function
    will default to run against network ranges returned in the ip_check_create function """
    _parser = argparse.ArgumentParser()
    _parser.add_argument('--network', help='define network to run provisioner agains', required=False, action='store')
    args=_parser.parse_args()

    if args.network: ip_check_create(args.network)

    else: ip_check_create()

if __name__ == '__main__': arg_input()
