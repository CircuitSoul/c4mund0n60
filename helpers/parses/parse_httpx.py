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
# from telegramBot import telegramNotification
from elasticInstance import getURLBase
from elasticInstance import getUser
from elasticInstance import getPass

# GET IP UTILS FOR ALL SCRIPTS
# sys.path.append('helpers/scripts')
# from ipUtils import RDAPgetStartAndEndAddress
# from ipUtils import rdap_domain
# from ipUtils import RDAPgetStartAndEndAddress
# from ipUtils import ip_block_to_cidr
from converTimezone import convertToUTC

target = sys.argv[1]
subdomain = sys.argv[2]
ip = sys.argv[3]
headers = {'Accept' : 'application/json', 'Content-Type' : 'application/json'}
url = getURLBase()+target+'-webenum/_doc?refresh'
auth=(getUser(), getPass())
hora = convertToUTC(strftime("%Y-%m-%dT%H:%M:%S%Z"))
scanner = 'httpx'
x = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+x+'-'+scanner
saida = hora+'-'+x+'.xml'
dic_web = {}

def executa(subdomain):
    result = subprocess.check_output('docker run --rm --name '+container_name+' -v $(pwd)/targets/'+target+'/temp:/data c4mund0n60-tools:1.0 /bin/bash -c "httpx -u '+subdomain+' -nc -sc -p 80,443,3000,3030,4000,5000,5001,5173,8443,8000,8080,8081,8082,8083,8084,8085,8086,10000,10443,19900 --silent" || true', shell=True)
    return (result.decode("utf-8").rstrip('\n'))

def parse():
	sistema = executa(subdomain)
	# sistema = 'http://teste.com:8080/uri1/uri2'
	if('http' in sistema or 'https' in sistema):
		dic_web['http.response.status_code'] = sistema.rstrip(' ').split('[')[1].split(']')[0]
		sistema = sistema.split('[')[0].rstrip(' ')

		dic_web['network.protocol'] = sistema.split(':')[0]
		try:
			dic_web['server.port'] = sistema.split(':')[2].split('/')[0]
		except:
			if(dic_web['network.protocol'] == 'http'):
				dic_web['server.port'] = '80'
			elif(dic_web['network.protocol'] == 'https'):
				dic_web['server.port'] = '443'
			else:
				pass
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
			'http.response.status_code': dic_web['http.response.status_code'],
			'url.original': dic_web['url.original'],
			'url.full': dic_web['url.original']+dic_web['url.path'],
			'vulnerability.scanner.vendor': scanner
		}
		r = requests.post(url=url, headers=headers, auth=auth, data=json.dumps(data), verify=False)
		print (r.text)

def main():
    parse()
    
if __name__== '__main__':
    main()