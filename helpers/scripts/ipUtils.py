import xml.etree.ElementTree as ET
import sys
import datetime
import socket
import requests
import subprocess
import os
import uuid
import shutil
import json
import time
from time import strftime
from pathlib import Path
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

scanner = 'rdap'
x = str(uuid.uuid1()).split('-')[0]

# GET ALL CONFIG INFORMATION
import sys
sys.path.append('helpers/configs')
from elasticInstance import getURLBase
from elasticInstance import getUser
from elasticInstance import getPass


def rdap_domain(domain):
    nameserver = ''
    try:
        consulta2 = requests.get('https://rdap.registro.br/domain/'+domain)
        json_rdap = json.loads(consulta2.text)
        for ns in json_rdap['nameservers']:
            nameserver = nameserver+ns['ldhName']+','
        return(nameserver[:-1])
    except:
        return('')
#Convert IP Address to CIDR
def ip_block_to_cidr(ip_start, ip_end):
    
    if (ip_start == '0.0.0.0' or ip_end == '0.0.0.0'):
        return('0.0.0.0/0')
    
    # Convert IP addresses to integer representation
    start = ip_to_int(ip_start)
    end = ip_to_int(ip_end)

    # Calculate the number of IP addresses in the block
    num_ips = end - start + 1

    # Find the subnet mask in CIDR notation
    subnet_mask = 32 - (num_ips.bit_length() - 1)

    # Write the network address in CIDR notation
    network_address = f"{ip_start}/{subnet_mask}"

    return network_address
def ip_to_int(ip_address):
    # Split the IP address into octets
    octets = ip_address.split('.')

    # Convert octets to integer representation
    ip_int = 0
    for octet in octets:
        ip_int = (ip_int << 8) + int(octet)

    return ip_int
def RDAPgetStartAndEndAddress(target,ip):
    container_name = target+'-'+x+'-'+scanner
    
    addressList = []
    
    if (ip == '0.0.0.0'):
        return('')
    else:
        try:
            getIPs = subprocess.check_output('docker run --rm --name '+container_name+' -v $(pwd)/targets/'+target+'/temp:/data c4mund0n60-tools:1.0 /bin/rdap '+ip+' --json || true', shell=True) 
            json_RDAPgetStartAndEndAddress = json.loads(getIPs)
            ipblock = json_RDAPgetStartAndEndAddress['handle']
            startAddress = json_RDAPgetStartAndEndAddress['startAddress']
            endAddress = json_RDAPgetStartAndEndAddress['endAddress']
            addressList.append(startAddress)
            addressList.append(endAddress)
            addressList.append(ipblock)
            return(addressList)
        except:
            return('')
        
def getInfosIPfromSubdomainIndex(target,ip):
    list_InfosIPfromSubdomainIndex = []
    
    url_get_ip_from_subdomain = getURLBase()+target+'-subdomain/_search'
    headers = {'Accept' : 'application/json', 'Content-Type' : 'application/json'}
    auth=(getUser(), getPass())
    data = {"size":10000}
    
    get_doc = requests.get(url_get_ip_from_subdomain, headers=headers, auth=auth, data=json.dumps(data), verify=False)
    parse_scan = json.loads(get_doc.text)
    for x in parse_scan['hits']['hits']:
        if(str(x['_source']['server.ip']) == str(ip)):
            if (str(x['_source']['server.ip']) not in list_InfosIPfromSubdomainIndex):
                list_InfosIPfromSubdomainIndex.append(x['_source']['server.startAddress'])
                list_InfosIPfromSubdomainIndex.append(x['_source']['server.endAddress'])
                list_InfosIPfromSubdomainIndex.append(x['_source']['server.ipblock'])
                return(list_InfosIPfromSubdomainIndex)