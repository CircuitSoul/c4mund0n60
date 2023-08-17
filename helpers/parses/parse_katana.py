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

import threading

# GET ALL CONFIG (Telegram and Elastic) INFORMATION
import sys
sys.path.append('helpers/configs')
from elasticInstance import getURLBase
from elasticInstance import getUser
from elasticInstance import getPass

# GET IP UTILS FOR ALL SCRIPTS
sys.path.append('helpers/scripts')
# from ipUtils import RDAPgetStartAndEndAddress
# from ipUtils import rdap_domain
# from ipUtils import RDAPgetStartAndEndAddress
# from ipUtils import ip_block_to_cidr
from converTimezone import convertToUTC

target = sys.argv[1]
url2 = sys.argv[2]
subdomain = sys.argv[3]
ip = sys.argv[4]
headers = {'Accept' : 'application/json', 'Content-Type' : 'application/json'}
url = getURLBase()+target+'-webenum/_doc?refresh'
urlConsultaKatanaIndex = getURLBase()+target+'-webenum/_search'
auth=(getUser(), getPass())
hora = convertToUTC(strftime("%Y-%m-%dT%H:%M:%S%Z"))
scanner = 'katana'
dic_web = {}
x = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+x+'-'+scanner
saida = scanner+'-'+x+'.txt'

list_qurl = []

def executa(url2):
    try:
        subprocess.check_output('docker run --rm --name '+container_name+' -v $(pwd)/targets/'+target+'/temp:/data c4mund0n60-tools:1.0 katana -u "'+url2+'" -f qurl -silent -rd 2 -o /data/'+saida+' 1>/dev/null || true', shell=True)
        return 1
    except subprocess.SubprocessError as e:
        print("Error na exec do docker with katana: ", e)
        return 0
    
def parse():
    with open('targets/'+target+'/temp/'+saida) as file:
        for line in file:
            newLine = line.strip('\n').strip(' ').strip(None)
            if (newLine not in list_qurl):
                list_qurl.append(newLine)

def submiteData(list_qurl):
    for unicURL in list_qurl:
        try:
            if(unicURL != '' or unicURL != ' ' or unicURL != None):
                dic_web['network.protocol'] = unicURL.split(':')[0]
                try:
                    if (len(unicURL.split('/')) == 3 and len(unicURL.split('?')) != 0):
                        dic_web['server.port'] = unicURL.split(':')[2].split('?')[0]
                    else:
                        dic_web['server.port'] = unicURL.split(':')[2].split('/')[0]
                except:
                    if(dic_web['network.protocol'] == 'http'):
                        dic_web['server.port'] = '80'
                    elif(dic_web['network.protocol'] == 'https'):
                        dic_web['server.port'] = '443'
                    elif(dic_web['network.protocol'] == 'ftp' or dic_web['network.protocol'] == 'sftp'):
                        dic_web['server.port'] = '21'
                    else:
                        dic_web['server.port'] = ''
                path = len(unicURL.split('/'))
                if(path == 3):
                    dic_web['url.path'] = '/'
                    dic_web['url.original'] = unicURL
                else:
                    i = 3
                    dic_web['url.path'] = ''
                    dic_web['url.original'] = dic_web['network.protocol']+'://'+unicURL.split('/')[2]
                    while i < path:
                        dic_web['url.path'] = dic_web['url.path']+'/'+unicURL.split('/')[i]
                        i += 1

                data = {
                '@timestamp': hora,
                'server.address': subdomain,
                'server.domain': subdomain,
                'server.ip': ip,
                'server.port': dic_web['server.port'],
                'network.protocol': dic_web['network.protocol'],
                'url.path': dic_web['url.path'],
                'http.response.status_code': '200',
                'url.original': dic_web['url.original'],
                'url.full': dic_web['url.original']+dic_web['url.path'],
                'vulnerability.scanner.vendor': scanner
                }
                r = requests.post(url=url, headers=headers, auth=auth, data=json.dumps(data), verify=False)
                print(r.text)
        except: 
            pass

def main():
    if (executa(url2) == 1):
        parse()
        
    submiteData(list_qurl)

if __name__== '__main__':
    main()
