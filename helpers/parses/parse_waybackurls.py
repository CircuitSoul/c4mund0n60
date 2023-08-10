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

# GET ALL CONFIG (Telegram and Elastic) INFORMATION
import sys
sys.path.append('helpers/configs')
from telegramBot import telegramNotification
from elasticInstance import getURLBase
from elasticInstance import getUser
from elasticInstance import getPass

# GET IP UTILS FOR ALL SCRIPTS
# sys.path.append('helpers/scripts')
# from ipUtils import RDAPgetStartAndEndAddress
# from ipUtils import rdap_domain
# from ipUtils import RDAPgetStartAndEndAddress
# from ipUtils import ip_block_to_cidr

target = sys.argv[1]
url2 = sys.argv[2]
subdomain = sys.argv[3]
ip = sys.argv[4]
headers = {'Accept' : 'application/json', 'Content-Type' : 'application/json'}
url = getURLBase()+target+'-webenum/_doc?refresh'
auth=(getUser(), getPass())
hora = strftime("%Y-%m-%dT%H:%M:%S%Z")
scanner = 'waybackurls'
dic_web = {}
x = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+x+'-'+scanner
saida = scanner+'-'+x+'.xml'

def executa(url2):
    result = subprocess.check_output('docker run --rm --name '+container_name+' -v $(pwd)/targets/'+target+'/temp:/data c4mund0n60-tools:1.0 /bin/bash -c "echo "'+url2+'" | waybackurls" || true', shell=True)
    return(result.decode("utf-8")[:-1].split('\n'))

def parse():
	list_sistemas = executa(url2)
	for sistema in list_sistemas:
		try:
			if(sistema != '' or sistema != None):
				dic_web['network.protocol'] = sistema.split(':')[0]
				try:
					dic_web['server.port'] = sistema.split(':')[2].split('/')[0]
				except:
					if(dic_web['network.protocol'] == 'http'):
						dic_web['server.port'] = '80'
					elif(dic_web['network.protocol'] == 'https'):
						dic_web['server.port'] = '443'
					elif(dic_web['network.protocol'] == 'ftp' or dic_web['network.protocol'] == 'sftp'):
						dic_web['server.port'] = '21'
					else:
						dic_web['server.port'] = ''
				path = len(sistema.split('/'))
				if(path == 3):
					dic_web['url.path'] = '/'
					dic_web['url.original'] = sistema
				else:
					i = 3
					dic_web['url.path'] = ''
					dic_web['url.original'] = dic_web['network.protocol']+'://'+sistema.split('/')[2]
					while i < path:
						dic_web['url.path'] = dic_web['url.path']+'/'+sistema.split('/')[i]
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
	parse()
    
if __name__== '__main__':
    main()
