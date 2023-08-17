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
from converTimezone import convertToUTC

target = sys.argv[1]
domain = sys.argv[2]
headers = {'Accept' : 'application/json', 'Content-Type' : 'application/json'}
url = getURLBase()+target+'-subdomain-temp/_doc?refresh'
auth=(getUser(), getPass())
hora = convertToUTC(strftime("%Y-%m-%dT%H:%M:%S%Z"))
scanner = 'subfinder'
dic_subdomain = {}
x = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+x+'-'+scanner
saida = scanner+'-'+x+'.txt'

def executa():
    subprocess.check_output('docker run --rm --name '+container_name+' -v $(pwd)/targets/'+target+'/temp:/data c4mund0n60-tools:1.0 subfinder -d '+domain+' -oJ -silent >> $(pwd)/targets/'+target+'/temp/'+saida+' || true', shell=True)
    return 1

def parse():
    with open ('targets/'+target+'/temp/'+saida) as json_file:
        for line in json_file:
            json_line = line.rstrip('\n')
            jsondata = json.loads(json_line)
            dic_subdomain['timestamp'] = hora
            dic_subdomain['server.address'] = jsondata['host']
            dic_subdomain['server.domain'] = jsondata['host']
            try:
                dic_subdomain['server.ip'] = socket.gethostbyname(jsondata['host'])
            except:
                dic_subdomain['server.ip'] = '0.0.0.0'
            dic_subdomain['vulnerability.scanner.vendor'] = scanner
            dic_subdomain['server.ipblock'] = RDAPgetStartAndEndAddress(target,dic_subdomain['server.ip']) 
            dic_subdomain['server.nameserver'] = rdap_domain(dic_subdomain['server.domain'])
            data = {
                    '@timestamp':dic_subdomain['timestamp'],
                    'server.address':dic_subdomain['server.address'],
                    'server.domain':dic_subdomain['server.domain'],
                    'server.ip':dic_subdomain['server.ip'],
                    'server.ipblock':dic_subdomain['server.ipblock'],
                    'server.nameserver':dic_subdomain['server.nameserver'],
                    'vulnerability.scanner.vendor':dic_subdomain['vulnerability.scanner.vendor']
            }
            r = requests.post(url, headers=headers, auth=auth, data=json.dumps(data), verify=False)
            print (r.text)

def main():
    if (executa() == 1):
        parse()
    
if __name__== '__main__':
    main()

