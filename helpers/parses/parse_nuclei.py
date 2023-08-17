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
# from telegramBot import telegramNotification
from elasticInstance import getURLBase
from elasticInstance import getUser
from elasticInstance import getPass

# GET IP UTILS FOR ALL SCRIPTS
# sys.path.append('helpers/scripts')
# from ipUtils import rdap_domain
# from ipUtils import RDAPgetStartAndEndAddress
# from ipUtils import ip_block_to_cidr
from converTimezone import convertToUTC

target = sys.argv[1]
sistema = sys.argv[2]
headers = {'Accept' : 'application/json', 'Content-Type' : 'application/json'}
url = getURLBase()+target+'-webvuln/_doc?refresh'
auth=(getUser(), getPass())
hora = convertToUTC(strftime("%Y-%m-%dT%H:%M:%S%Z"))
scanner = 'nuclei'
x = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+x+'-'+scanner
saida = scanner+'-'+x+'.json'
dic_web = {}
dic_infra = {}

def executa(sistema):
    try:
        subprocess.check_output('docker run --rm --name '+container_name+' -v $(pwd)/targets/'+target+'/temp:/data c4mund0n60-tools:1.0 nuclei -u '+sistema+' -t /root/nuclei-templates/ -silent -jle /data/'+saida+' || true', shell=True)
        return 1
    except subprocess.SubprocessError as e:
        print("Error na exec do docker with nuclei: ", e)
        return 0

def parse():
    with open('targets/'+target+'/temp/'+saida) as jsonfile:
        for linejson in jsonfile:
            jsonline = linejson.rstrip('\n')
            jsondata = json.loads(jsonline)
            for i in jsondata:
                if('http' in jsondata['matched-at'] or 'https' in jsondata['matched-at']):
                    url = getURLBase()+target+'-webvuln/_doc?refresh'
                    dic_web['vulnerability.name'] = jsondata['info']['name']
                    dic_web['vulnerability.severity'] = jsondata['info']['severity']
                    try:
                        dic_web['vulnerability.description']= jsondata['info']['description']
                    except:
                        dic_web['vulnerability.description'] = jsondata['info']['name']
                    dic_web['url.original'] = jsondata['host']
                    try:
                        dic_web['vulnerability.description'] = dic_web['vulnerability.description']+' '+jsondata['matcher-name']
                    except:
                        pass
                    dic_web['url.full'] = jsondata['matched-at']
                    try:
                        dic_web['server.ip'] = jsondata['ip']
                    except:
                        dic_web['server.ip'] = '0.0.0.0'
                    try:
                        dic_web['reference'] = jsondata['info']['reference']
                    except:
                        dic_web['reference'] = ''
                    try:
                        dic_web['network.protocol'] = jsondata['host'].split(':')[0]
                    except:
                        dic_web['network.protocol'] = '0'    
                    try: 
                        dic_web['server.address'] = sys.argv[3]
                        dic_web['server.domain'] = dic_web['server.address']
                        dic_web['server.port'] = sys.argv[4]
                        dic_web['url.path'] = sys.argv[5]
                        dic_web['http.response.status_code'] = '200'
                    except:
                        print("Error in parse_nuclei.py file, looks like this values: dic_web['server.address'], dic_web['server.domain'], dic_web['server.port'], dic_web['url.path'], dic_web['http.response.status_code'] ", )
                    data = {
                    '@timestamp':hora,
                    'server.address':dic_web['server.address'],
                    'server.domain':dic_web['server.domain'],
                    'server.ip':dic_web['server.ip'],
                    'server.port':dic_web['server.port'],
                    'network.protocol':dic_web['network.protocol'],
                    'service.name' : 'N/A',
                    'url.path':dic_web['url.path'],
                    'http.response.status_code':dic_web['http.response.status_code'],
                    'vulnerability.description':dic_web['vulnerability.description'],
                    'vulnerability.name':dic_web['vulnerability.name'],
                    'vulnerability.severity':dic_web['vulnerability.severity'],
                    'url.original':dic_web['url.original'],
                    'url.full':dic_web['url.full'],
                    'vulnerability.scanner.vendor':scanner
                    }
                else:
                    url = getURLBase()+target+'-infravuln/_doc?refresh'
                    dic_infra['server.address'] = sys.argv[3]
                    dic_infra['vulnerability.name'] = jsondata['info']['name']
                    dic_infra['vulnerability.severity'] = jsondata['info']['severity']
                    try:
                        dic_infra['vulnerability.description'] = jsondata['info']['description']
                    except:
                        dic_infra['vulnerability.description']= jsondata['info']['name']
                    try:
                        dic_infra['vulnerability.description'] = dic_infra['vulnerability.description']+' '+jsondata['matcher-name']
                    except:
                        pass
                    try:
                        dic_infra['server.ip'] = jsondata['ip']
                    except:
                        dic_infra['server.ip'] = '0.0.0.0'
                    try:
                        dic_infra['server.port'] = jsondata['matched-at'].split(':')[1]
                    except:
                        dic_infra['server.port'] = sys.argv[4]
                    dic_infra['network.protocol'] = 'N/A'
                    if(dic_infra['server.port'] == '22'):
                        dic_infra['network.protocol'] = 'ssh'
                    if(dic_infra['server.port'] == '21'):
                        dic_infra['network.protocol'] = 'ftp'
                    if(dic_infra['server.port'] == '23'):
                        dic_infra['network.protocol'] = 'telnet'
                    if(dic_infra['server.port'] == '3389'):
                        dic_infra['network.protocol'] = 'rdp'
                    if(dic_infra['server.port'] == '445'):
                        dic_infra['network.protocol'] = 'smb'
                    if(dic_infra['server.port'] == '88'):
                        dic_infra['network.protocol'] = 'kerberos'
                    data = {
                        '@timestamp':hora,
                        'server.address':dic_infra['server.address'],
                        'server.ip':dic_infra['server.ip'],
                        'server.port':dic_infra['server.port'],
                        'network.protocol':dic_infra['network.protocol'],
                        'service.name' : 'N/A',
                        'vulnerability.description':dic_infra['vulnerability.description'],
                        'vulnerability.name':dic_infra['vulnerability.name'],
                        'vulnerability.severity':dic_infra['vulnerability.severity'],
                        'vulnerability.scanner.vendor':scanner
                    }
                    r = requests.post(url=url, headers=headers, auth=auth, data=json.dumps(data), verify=False)
                    print(r.text)

def main():
    executa(sistema)
    parse()
    
if __name__== '__main__':
    main()
