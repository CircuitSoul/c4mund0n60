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
# from ipUtils import rdap_domain
from ipUtils import RDAPgetStartAndEndAddress
from ipUtils import ip_block_to_cidr

target = sys.argv[1]
domain = sys.argv[2]
headers = {'Accept' : 'application/json', 'Content-Type' : 'application/json'}
url = getURLBase()+target+'-subdomain-temp/_doc?refresh'
auth=(getUser(), getPass())
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = 'amass'
dic_subdomain = {}
x = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+x+'-'+scanner
saida = scanner+'-'+x+'.json'

def executa():
    subprocess.check_output('docker run --rm --name '+container_name+' -v $(pwd)/targets/'+target+'/temp:/data c4mund0n60-tools:1.0 amass enum -d '+domain+' -nocolor -dns-qps 5 -silent -json /data/'+saida+' || true', shell=True)
    return 1

def populate_list_with_ip_cidr(ip,cidr):
    list_ip_cidr = []
    list_ip_cidr.append([ip,cidr])
    return list_ip_cidr #example : [['185.199.108.153', '185.199.108.0/22']]

def parseAjustado():
    list_ip_cidr = []
    
    with open ('targets/'+target+'/temp/'+saida) as jsonFile:
    # with open('/home/op/amass-example.json') as jsonFile:
        for fileLine in jsonFile:
            jsonLine = fileLine.rstrip('\n')
            json_data = json.loads(jsonLine)
            for parseIP in json_data['addresses']:
                if (('::') not in parseIP['ip']):
                    list_ip_cidr = populate_list_with_ip_cidr(parseIP['ip'],parseIP['cidr'])
            
            for ip in list_ip_cidr:
                dic_subdomain['timestamp'] = hora
                dic_subdomain['server.address'] = json_data['name']
                dic_subdomain['server.domain'] = json_data['domain']
                dic_subdomain['server.nameserver'] = socket.gethostbyname(dic_subdomain['server.domain'])
                dic_subdomain['server.ip'] = ip[0]
                dic_subdomain['server.startAddress'] = RDAPgetStartAndEndAddress(target,dic_subdomain['server.ip'])[0]
                dic_subdomain['server.endAddress'] = RDAPgetStartAndEndAddress(target,dic_subdomain['server.ip'])[1]
                dic_subdomain['server.ipblock'] = RDAPgetStartAndEndAddress(target,dic_subdomain['server.ip'])[2]
                try:
                    dic_subdomain['server.cidr'] = ip[1]
                except:
                    print('[+] TRYNG RESOLVE CIDR FROM IPBLOCK: ', dic_subdomain['server.ip'])
                    dic_subdomain['server.cidr'] = ip_block_to_cidr(dic_subdomain['server.startAddress'],dic_subdomain['server.endAddress'])
                dic_subdomain['vulnerability.scanner.vendor'] = 'amass'
                data = {
                        '@timestamp':dic_subdomain['timestamp'],
                        'server.address':dic_subdomain['server.address'],
                        'server.domain':dic_subdomain['server.domain'], 
                        'server.nameserver':dic_subdomain['server.nameserver'],
                        'server.ip':dic_subdomain['server.ip'],
                        'server.startAddress':dic_subdomain['server.startAddress'],
                        'server.endAddress':dic_subdomain['server.endAddress'],
                        'server.ipblock':dic_subdomain['server.ipblock'],
                        'server.cidr':dic_subdomain['server.cidr'],
                        'vulnerability.scanner.vendor':dic_subdomain['vulnerability.scanner.vendor']
                }
                # print(data)
                r = requests.post(url, headers=headers, auth=auth, data=json.dumps(data), verify=False)
                print (r.text)
    return 1

def main():
    if (executa() == 1):
        parseAjustado()
    
if __name__== '__main__':
    main()
