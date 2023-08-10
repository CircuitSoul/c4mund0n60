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

#GET API KEY Virus Total
from apiKeys import getVTAPIKEY

# GET IP UTILS FOR ALL SCRIPTS
sys.path.append('helpers/scripts')
from ipUtils import rdap_domain
from ipUtils import RDAPgetStartAndEndAddress
from ipUtils import ip_block_to_cidr

target = sys.argv[1]
domain = sys.argv[2]
headers = {'Accept' : 'application/json', 'Content-Type' : 'application/json'}
url = getURLBase()+target+'-subdomain-temp/_doc?refresh'
auth=(getUser(), getPass())
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = 'vtsubdomains'
dic_subdomain = {}
x = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+x+'-'+scanner
saida = scanner+'-'+x+'.txt'

def executa():
    subprocess.check_output('docker run --rm --name '+container_name+' -v $(pwd)/helpers/scripts:/scripts -v $(pwd)/targets/'+target+'/temp:/data c4mund0n60-tools:1.0 python3 /scripts/vt-subdomains.py '+domain+' '+getVTAPIKEY()+' >> $(pwd)/targets/'+target+'/temp/'+saida+' || true', shell=True)
    return 1

def parse():
    with open ('targets/'+target+'/temp/'+saida) as file:
        for line in file:
            dic_subdomain['timestamp'] = hora
            dic_subdomain['server.address'] = line.rstrip('\n')
            dic_subdomain['server.domain'] = line.rstrip('\n')
            try:
                dic_subdomain['server.ip'] = socket.gethostbyname(line.rstrip('\n'))
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
            #print(data)

def main():
    if (executa() == 1):
        parse()
    
if __name__== '__main__':
    main()
