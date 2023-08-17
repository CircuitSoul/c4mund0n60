#!/usr/bin/env python3

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


# GET ALL CONFIG INFORMATION
import sys
sys.path.append('helpers/configs')
from telegramBot import telegramNotification
from elasticInstance import getURLBase
from elasticInstance import getUser
from elasticInstance import getPass

# GET IP UTILS FOR ALL SCRIPTS
sys.path.append('helpers/scripts')
from ipUtils import rdap_domain
from ipUtils import RDAPgetStartAndEndAddress
from ipUtils import ip_block_to_cidr
from ipUtils import getInfosIPfromSubdomainIndex
from converTimezone import convertToUTC

#GLOBAL INFOS
target = sys.argv[1]
ip = sys.argv[2]
headers = {'Accept' : 'application/json', 'Content-Type' : 'application/json'}
url_post = getURLBase()+target+'-portscan/_doc?refresh'
url_get = getURLBase()+target+'-subdomain/_search'
auth=(getUser(), getPass())
hora = convertToUTC(strftime("%Y-%m-%dT%H:%M:%S%Z"))
scanner = 'rustscan'
dic_ports = {}
x = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+x+'-'+scanner
saida = scanner+'-'+x+'.xml'

list_ports = []

def executa():
    resultPorts = subprocess.check_output('docker run --name '+container_name+' --rm -v $(pwd)/targets/'+target+'/temp:/home/rustscan rustscan/rustscan:latest --accessible --greppable --no-config --ulimit 1000 --range 1-65535 -a '+ip+' || true', shell=True)
    try:
        resultPorts = resultPorts.decode('utf-8').rstrip('\r\n').replace('[','').replace(']','').replace(' ','').split('->')[1].split(',')
    except:
        resultPorts = []
    for port in resultPorts:
        list_ports.append(port)
    # print(list_ports)
    time.sleep(3)
    return 1

def parse():
    for port in list_ports:
        dic_ports['timestamp'] = hora
        dic_ports['server.address'] = ip
        dic_ports['network.protocol'] = 'tcp'
        dic_ports['server.ip'] = ip
        try:
            dic_ports['server.port'] = port
        except:
            dic_ports['server.port'] = ''
        try:
            dic_ports['server.startAddress'] = getInfosIPfromSubdomainIndex(target,dic_ports['server.ip'])[0]
            dic_ports['server.endAddress'] = getInfosIPfromSubdomainIndex(target,dic_ports['server.ip'])[1]
            dic_ports['server.ipblock'] = getInfosIPfromSubdomainIndex(target,dic_ports['server.ip'])[2]
        except:
            try:
                dic_ports['server.startAddress'] = RDAPgetStartAndEndAddress(target,dic_ports['server.ip'])[0]
                dic_ports['server.endAddress'] = RDAPgetStartAndEndAddress(target,dic_ports['server.ip'])[1]
                dic_ports['server.ipblock'] = RDAPgetStartAndEndAddress(target,dic_ports['server.ip'])[2]
            except:
                dic_ports['server.startAddress'] = '0.0.0.0'
                dic_ports['server.endAddress'] = '0.0.0.0'
                dic_ports['server.ipblock'] = '0.0.0.0'
        try:
            dic_ports['server.cidr'] = ip_block_to_cidr(dic_ports['server.startAddress'],dic_ports['server.endAddress'])
        except:
            dic_ports['server.cidr'] = '0.0.0.0/0'
        dic_ports['service.name'] = ''
        dic_ports['service.state'] = 'open'
        dic_ports['application.version.number'] = ''
        dic_ports['network.transport'] = 'tcp'
        dic_ports['network.type'] = 'ipv4'
        dic_ports['vulnerability.scanner.vendor'] = scanner
        
        data = {
                '@timestamp':hora,
                'server.address':ip,
                'network.protocol':dic_ports['network.protocol'],
                'server.ip':ip,
                'server.port':dic_ports['server.port'],
                'server.ipblock':dic_ports['server.ipblock'],
                'server.startAddress': dic_ports['server.startAddress'],
                'server.endAddress': dic_ports['server.endAddress'],
                'server.cidr': dic_ports['server.cidr'],
                'server.name':dic_ports['service.name'],
                'server.state':dic_ports['service.state'],
                'network.transport':dic_ports['network.transport'],
                'network.type':dic_ports['network.type'],
                'application.version.number':dic_ports['application.version.number'],
                'vulnerability.scanner.vendor':scanner
        }
        # print(str(data)+'\n')
        r = requests.post(url_post, headers=headers, auth=auth, data=json.dumps(data), verify=False)
        print (r.text)
            
def main():
    executa()
    if (executa() == 1):
        parse()
    
if __name__== '__main__':
    main()
