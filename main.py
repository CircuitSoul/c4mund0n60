import xml.etree.ElementTree as ET
import datetime
import socket
import requests
import subprocess
import os
import uuid
import shutil
import json
import time
import telegram
from time import strftime
from pathlib import Path
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import re

# GET ALL CONFIG (Telegram and Elastic) INFORMATION
import sys
sys.path.append('helpers/configs')
from telegramBot import telegramNotification
from elasticInstance import getURLBase
from elasticInstance import getUser
from elasticInstance import getPass

# GET IP UTILS FOR ALL SCRIPTS
sys.path.append('helpers/scripts')
from ipUtils import RDAPgetStartAndEndAddress
from ipUtils import rdap_domain
from ipUtils import RDAPgetStartAndEndAddress
from ipUtils import ip_block_to_cidr

# GET parallels functions
sys.path.append('helpers/parallel')
from parallels import parallel_subdomainTemp
from parallels import parallel_rustscan
from parallels import parallel_httpx
from parallels import parallel_nuclei
from parallels import parallel_waybackurls
from parallels import parallel_katana

# GLOBAL VARIABLES
target = sys.argv[1]
headers = {'Accept' : 'application/json', 'Content-Type' : 'application/json'}
url = getURLBase()+target+'-subdomain/_search'
url_temp = getURLBase()+target+'-subdomain-temp/_search'
url_post = getURLBase()+target+'-subdomain/_doc?refresh'
url_applications = getURLBase()+target+'-webenum/_search'
url_web = getURLBase()+target+'-webvuln/_search'
auth=(getUser(), getPass())
hora = strftime("%Y-%m-%dT%H:%M:%S")
scanner = 'c4mund0n60-monitoring'
x = str(uuid.uuid1()).split('-')[0]
container_name = target+'-'+x+'-'+scanner
dic_subdomain = {}
list_subs = []
list_subs_novos = []
list_rustscan = []
dic_serv = {}
dic_subs_novos = {}
dic_applications = {}

# FLOW EXECUTION 
def create_indices():
    try:
        #CREATE index OSINT
        # print("[+] Create index OSINT")
        # url_osint =  str(getURLBase()+target+'-osint')
        # dataCreateOsint = {
        #     "mappings":{
        #         "properties":{
        #         "@timestamp":{"type":"date"},
        #         "server.address": {"type":"keyword"},
        #         "server.domain": {"type":"keyword"},
        #                 "server.nameserver": {"type":"keyword"},
        #         "server.ip": {"type":"ip"},
        #                 "server.ipblock": {"type":"keyword"},
        #         "vulnerability.scanner.vendor": {"type":"keyword"}
        #         }
        #     }
        # }
        # rCreateOsint = requests.put(url=url_osint,headers=headers,auth=auth,data=json.dumps(dataCreateOsint),verify=False)
        
        #CREATE index SUBDOMAIN
        print("[+] Create index SUBDOMAIN")
        url_subdomain = str(getURLBase()+target+'-subdomain')
        dataCreateSubdomain = {
            "mappings":{
                "properties":{
                "@timestamp":{
                    "type":"date",
                    "format": "strict_date_optional_time||epoch_millis"
                    },
                "server.address": {"type":"keyword"},
                "server.domain": {"type":"keyword"},
                        "server.nameserver": {"type":"keyword"},
                "server.ip": {"type":"ip"},
                        "server.ipblock": {"type":"keyword"},
                        "server.startAddress": {"type":"ip"},
                        "server.endAddress": {"type":"ip"},
                        "server.cidr": {"type":"keyword"},
                "vulnerability.scanner.vendor": {"type":"keyword"}
                }
            }
        }
        rCreateSubdomain = requests.put(url=url_subdomain,headers=headers,auth=auth,data=json.dumps(dataCreateSubdomain),verify=False)
        
        #CREATE index PORTSCAN
        print("[+] Create index PORT SCANNING")
        url_portscan =  str(getURLBase()+target+'-portscan')
        dataCreatePortscan = {
            "mappings":{
                "properties":{
                "@timestamp":{
                    "type":"date",
                    "format": "strict_date_optional_time||epoch_millis"
                    },
                "server.address": {"type":"keyword"},
                "network.protocol": {"type":"keyword"},
                "server.ip": {"type":"ip"},
                        "server.port": {"type":"long"},
                        "server.startAddress": {"type":"ip"},
                        "server.endAddress": {"type":"ip"},
                        "server.ipblock": {"type":"keyword"},
                                "server.cidr": {"type":"keyword"},
                        "service.name": {"type":"keyword"},
                "service.state": {"type":"keyword"},
                        "application.version.number": { "type":"keyword"},
                        "network.transport": {"type":"keyword"},
                    "network.type": {"type":"keyword"},
                "vulnerability.scanner.vendor": {"type":"keyword"}
                }
            }
        }
        rCreatePortScan = requests.put(url=url_portscan,headers=headers,auth=auth,data=json.dumps(dataCreatePortscan),verify=False)
        
        #CREATE index WEB ENUM
        print("[+] Create index WEB ENUM")
        url_webenum =  str(getURLBase()+target+'-webenum')
        dataCreateWebenum = {
            "mappings":{
                "properties":{
                    "@timestamp":{
                        "type":"date",
                        "format": "strict_date_optional_time||epoch_millis"
                        },
                    "server.address": {"type":"keyword"},
                            "server.domain": {"type":"keyword"},
                    "server.ip": {"type":"ip"},
                            "server.port": {"type":"long"},
                            "network.protocol": {"type":"keyword"},
                            "url.path": {"type":"keyword"},
                            "http.response.status_code": {"type":"long"},
                            "url.original": {"type":"keyword"},
                        "url.full": {"type":"keyword"},
                    "vulnerability.scanner.vendor": {"type":"keyword"}
                }
            }
        }
        rCreateWebenum = requests.put(url=url_webenum,headers=headers,auth=auth,data=json.dumps(dataCreateWebenum),verify=False)
        
        #CREATE index WEB VULN
        print("[+] Create index WEB VULN")
        url_webvuln =  str(getURLBase()+target+'-webvuln')
        dataCreateWebvuln = {
            "mappings":{
                "properties":{
                    "@timestamp":{
                        "type":"date",
                        "format": "strict_date_optional_time||epoch_millis"
                        },
                    "server.address": {"type":"keyword"},
                            "server.domain": {"type":"keyword"},
                    "server.ip": {"type":"ip"},
                            "server.port": {"type":"long"},
                            "network.protocol": {"type":"keyword"},
                            "service.name": {"type":"keyword"},
                            "url.path": {"type":"keyword"},
                            "http.response.status_code": {"type":"long"},
                            "vulnerability.description": {"type":"keyword"},
                            "vulnerability.name": {"type":"keyword"},
                            "vulnerability.severity": {"type":"keyword"},
                            "url.original": {"type":"keyword"},
                        "url.full": {"type":"keyword"},
                    "vulnerability.scanner.vendor": {"type":"keyword"}
                }
            }
        }
        rCreateWebvuln = requests.put(url=url_webvuln,headers=headers,auth=auth,data=json.dumps(dataCreateWebvuln),verify=False)
        
        #CREATE index INFRA VULN
        print("[+] Create index INFRA VULN")
        url_infravuln =  str(getURLBase()+target+'-infravuln')
        dataCreateInfravuln = {
            "mappings":{
                "properties":{
                    "@timestamp":{
                        "type":"date",
                        "format": "strict_date_optional_time||epoch_millis"
                        },
                    "server.address": {"type":"keyword"},
                            "server.domain": {"type":"keyword"},
                    "server.ip": {"type":"ip"},
                            "server.port": {"type":"long"},
                            "network.protocol": {"type":"keyword"},
                            "service.name": {"type":"keyword"},
                            "url.path": {"type":"keyword"},
                            "http.response.status_code": {"type":"long"},
                            "vulnerability.description": {"type":"keyword"},
                            "vulnerability.name": {"type":"keyword"},
                            "vulnerability.severity": {"type":"keyword"},
                            "url.original": {"type":"keyword"},
                        "url.full": {"type":"keyword"},
                    "vulnerability.scanner.vendor": {"type":"keyword"}
                }
            }
        }
        rCreateInfravuln = requests.put(url=url_infravuln,headers=headers,auth=auth,data=json.dumps(dataCreateInfravuln),verify=False)
        
        return 1
    except:
        print("Error in create_indices function")
        return 0
    
def executa():
    url_in_executa_scope = str(getURLBase()+target+'-subdomain-temp')
    
    #DELETE INDEX SUBDOMAINS TEMP
    print("[+] Delete index SUBDOMAIN TEMP")
    rDelete = requests.delete(url_in_executa_scope,headers=headers,auth=auth,verify=False)
    
    #CREATE INDEX SUBDOMAINS TEMP
    print("[+] Create index SUBDOMAIN TEMP")
    dataCreate = {
        "mappings":{
            "properties":{
            "@timestamp":{"type":"date"},
            "server.address": {"type":"keyword"},
            "server.domain": {"type":"keyword"},
            "server.nameserver": {"type":"keyword"},
            "server.ip": {"type":"ip"},
            "server.ipblock": {"type":"keyword"},
            "server.startAddress": {"type":"ip"},
            "server.endAddress": {"type":"ip"},
            "server.cidr": {"type":"keyword"},
            "vulnerability.scanner.vendor": {"type":"keyword"}
            }
        }
    }
    rCreate = requests.put(url_in_executa_scope,headers=headers,auth=auth,data=json.dumps(dataCreate),verify=False)
    
    #START ENUMERATE SUBDOMAINS TEMP
    os.system('rm -rf targets/'+target+'/temp/*')
    msg = "[+] Start SUBDOMAIN ENUMERATION"
    print(msg)
    with open('targets/'+target+'/domains.txt') as domainsFile:
        for domain in domainsFile:
            parallel_subdomainTemp(target,domain)

def consulta_subdomain_base(): #This function return the subdomains previously registred 
    data = {"size":10000}
    getSubdomains = requests.get(url, headers=headers, auth=auth, data=json.dumps(data), verify=False)
    parse_scan = json.loads(getSubdomains.text)
    for x in parse_scan['hits']['hits']:
        if((x['_source']['server.domain']) not in list_subs):
            list_subs.append((x['_source']['server.domain']))
def consulta_subdomain_novos(): #This function return the news subdomains found 
    data = {"size":10000}
    get_doc = requests.get(url_temp, headers=headers, auth=auth, data=json.dumps(data), verify=False)
    parse_scan = json.loads(get_doc.text)
    for x in parse_scan['hits']['hits']:
        if(str(x['_source']['server.domain']) not in list_subs and str(x['_source']['server.domain']) not in list_subs_novos):
            list_subs_novos.append(x['_source']['server.domain'])

def encadeamento_rustscan(list_rustscan):
    dic_serv_with_ip = parallel_rustscan(target,list_rustscan,dic_serv)
    time.sleep(1)
    url_rustscan = getURLBase()+target+'-portscan/_search'
    data = {"size":10000}
    get_doc = requests.get(url_rustscan, headers=headers, auth=auth, data=json.dumps(data), verify=False)
    parse_scan = json.loads(get_doc.text)
    for x in parse_scan['hits']['hits']:
        if(x['_source']['server.ip'] in list_rustscan):
            if(x['_source']['server.port'] not in dic_serv_with_ip[x['_source']['server.ip']]):
                dic_serv_with_ip[x['_source']['server.ip']].append(x['_source']['server.port'])
    for ip in dic_serv_with_ip:
        message = ip,' port: ',dic_serv_with_ip[ip]
        time.sleep(1)
        try:
            telegramNotification(message)
        except telegram.error.TelegramError as e:
            telegramNotification(e)
def encadeamento_httpx(dic_subs_novos):
    parallel_httpx(target,dic_subs_novos)
def encadeamento_waybackurls():
    dic_subs_novos_waybackurls = {}
    data = {"size":10000}
    get_doc = requests.get(url_applications, headers=headers, auth=auth, data=json.dumps(data), verify=False)
    parse_scan = json.loads(get_doc.text)
    for x in parse_scan['hits']['hits']:
        if(str(x['_source']['url.original']) not in dic_subs_novos_waybackurls):
            dic_subs_novos_waybackurls[x['_source']['url.original']] = [x['_source']['server.domain'],x['_source']['server.ip']]
    
    parallel_waybackurls(target,dic_subs_novos_waybackurls)
def encadeamento_katana(target):
    dic_subs_novos_katana = {}
    data = {"size":10000}
    get_doc = requests.get(url_applications, headers=headers, auth=auth, data=json.dumps(data), verify=False)
    parse_scan = json.loads(get_doc.text)
    for x in parse_scan['hits']['hits']:
        if(str(x['_source']['url.original']) not in dic_subs_novos_katana):
            dic_subs_novos_katana[x['_source']['url.original']] = [x['_source']['server.domain'],x['_source']['server.ip']]
    
    parallel_katana(target,dic_subs_novos_katana)
def encadeamento_nuclei(dic_subs_novos):
    data = {"size":10000}
    get_applications = requests.get(url_applications, headers=headers, auth=auth, data=json.dumps(data), verify=False)
    applications_data = json.loads(get_applications.text)
    for x in applications_data['hits']['hits']:
        if(str(x['_source']['url.original']) not in dic_applications):
            dic_applications[x['_source']['url.original']] = [x['_source']['server.domain'],x['_source']['server.port'],x['_source']['url.path']]
    
    parallel_nuclei(target,dic_applications,dic_subs_novos)
    
    #This follow block code make a new vuln list for send a telegram chat
    get_applications = requests.get(url_web, headers=headers, auth=auth, data=json.dumps(data), verify=False)
    applications_data = json.loads(get_applications.text)
    for x in applications_data['hits']['hits']:
        if(x['_source']['server.domain'] in dic_subs_novos):
            if(x['_source']['vulnerability.severity'] in ['info','low','',' ']):
                pass
            else:
                message = (x['_source']['url.original'],x['_source']['vulnerability.name'],x['_source']['vulnerability.severity'])
                time.sleep(1)
                try:
                    telegramNotification(message)
                except telegram.error.TelegramError as e:
                    telegramNotification(e)

def parse():
    for line in list_subs_novos:
    # for line in list_subs:
        dic_subdomain['server.address'] = line.rstrip('\n')
        dic_subdomain['server.domain'] = line.rstrip('\n')
        try:
            dic_subdomain['server.ip'] = socket.gethostbyname(line.rstrip('\n'))
        except:
            dic_subdomain['server.ip'] = '0.0.0.0'
            
        if(dic_subdomain['server.ip'] not in list_rustscan):
            list_rustscan.append(dic_subdomain['server.ip'])
        else:
            pass
        
        dic_subdomain['vulnerability.scanner.vendor'] = scanner
        dic_subdomain['server.nameserver'] = rdap_domain(dic_subdomain['server.domain'])
        try:
            dic_subdomain['server.startAddress'] = RDAPgetStartAndEndAddress(target,dic_subdomain['server.ip'])[0]
            dic_subdomain['server.endAddress'] = RDAPgetStartAndEndAddress(target,dic_subdomain['server.ip'])[1]
            dic_subdomain['server.ipblock'] = RDAPgetStartAndEndAddress(target,dic_subdomain['server.ip'])[2]
        except:
            dic_subdomain['server.startAddress'] = '0.0.0.0'
            dic_subdomain['server.endAddress'] = '0.0.0.0'
            dic_subdomain['server.ipblock'] = '0.0.0.0'
        try:
            dic_subdomain['server.cidr'] = ip_block_to_cidr(dic_subdomain['server.startAddress'],dic_subdomain['server.endAddress'])
        except:
            dic_subdomain['server.cidr'] = '0.0.0.0/0'
        
        data = {
                 '@timestamp':hora,
                 'server.address':dic_subdomain['server.address'],
                 'server.domain':dic_subdomain['server.domain'],
                 'server.ip':dic_subdomain['server.ip'],
                 'server.ipblock':dic_subdomain['server.ipblock'],
                 'server.startAddress':dic_subdomain['server.startAddress'],
                 'server.endAddress':dic_subdomain['server.endAddress'],
                 'server.cidr':dic_subdomain['server.cidr'],
                 'server.nameserver':dic_subdomain['server.nameserver'],
                 'vulnerability.scanner.vendor':dic_subdomain['vulnerability.scanner.vendor']
        }
        r = requests.post(url_post, headers=headers, auth=auth, data=json.dumps(data), verify=False)
        print (r.text)
        message = "[+] New Subdomain finded - "+dic_subdomain['server.domain']+' - '+dic_subdomain['server.ip']
        time.sleep(3)
        
        try:
            telegramNotification(message)
        except telegram.error.TelegramError as e:
            telegramNotification(e)
        
        try:
            dic_subs_novos[dic_subdomain['server.domain']] = dic_subdomain['server.ip']
        except:
            pass
    encadeamento_rustscan(list_rustscan)
    encadeamento_httpx(dic_subs_novos)
    encadeamento_waybackurls()
    encadeamento_katana(target)
    encadeamento_nuclei(dic_subs_novos)

# UTILITY FUNCTIONS
def menu(): #melhorar esse menu
    camundogoArt = '''                                                                           
              @,,,.#         #@@@%/                                             
            &,,/*,,,,,@.&&.,,,,,,,,,,,,.*@                                      
            .,@,,,,,,,,#,,,,,,,,,,,,,,,,,,,,.@                                  
          /%,,&,,,,,,,@,,,,,,,,,,,,,,,,,,,,,,,,,.&                              
       *,,,,,,.*,,,,,*,,,,,,,,,,,,,,,,,,,,,,,,,,,,,@                            
      &,,,,,,,,,@,#(,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,@                          
    #.,,,@@@,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,@                         
   @,,,,,..,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,.(                        
  %,,,,,,,..*#%*,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,#                     *@ 
&@@&%#/,....,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,(,,,,,,,*/%@@@%,  *@%,   
   @# .# @   @.,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,(&@,(&             /(        
                  @*@,,,,,,,,,,,,,,,,,,,,,,,,,,.&@*@**                          
           ,/#%%#(%.@*.,(&@&(*                 *%@*@,*                         
    '''
    print(camundogoArt)
    print('c4mund0n60 Tool')
    print('Create project: sh '+os.getcwd()+'/initProject.sh' + ' <project>')
    print('Start project: python3 ' + sys.argv[0] + ' <project>')
    print('Delete project: python3 ' + sys.argv[0] + ' <project>' + ' --delete')
    exit(0)
def deleteProject(project):
    url_base = getURLBase()+project
    url_subdomain = getURLBase()+project+'-subdomain'
    url_portscan = getURLBase()+project+'-portscan'
    url_webenum = getURLBase()+project+'-webenum'
    url_webvuln = getURLBase()+project+'-webvuln'
    url_infravuln = getURLBase()+project+'-infravuln'
    try:
        requests.delete(url_base, headers=headers, auth=auth, verify=False)
        requests.delete(url_subdomain, headers=headers, auth=auth, verify=False)
        requests.delete(url_portscan, headers=headers, auth=auth, verify=False)
        requests.delete(url_webenum, headers=headers, auth=auth, verify=False)
        requests.delete(url_webvuln, headers=headers, auth=auth, verify=False)
        requests.delete(url_infravuln, headers=headers, auth=auth, verify=False)
    except requests.ConnectionError as e:
        print("Delete error: ", e)
    
    try:
        projectPath = os.getcwd()+'/targets/'+project
        if os.path.exists(projectPath):
            shutil.rmtree(projectPath)
            return 1
    except:
        print("Error in delete project folder and files")
        return 0
        
def verifyProjectExist(project):
    path = os.getcwd()+'/targets/'+project
    if os.path.exists(path):
        return 1
    else:
        return 0

# MAIN FUNCTION
def main():
    project = sys.argv[1]
    if (verifyProjectExist(project)) == 0:
        menu()       
    try:
        if len(sys.argv) == 2:
            pattern = r'^[a-zA-Z0-9]+$'
            if re.match(pattern, sys.argv[1]):
                create_indices()
                executa()
                consulta_subdomain_base()
                consulta_subdomain_novos()
                parse()
            else:
                print("caracter in argument not permitted project name NEED follow this regular expression: ^[a-zA-Z0-9]+$ \n")
                menu()
        elif (len(sys.argv) == 1 or sys.argv[1] == '' or sys.argv[1] == ' ' or sys.argv[1] == None):
            menu()
        elif (len(sys.argv) == 2 and sys.argv[2] != '--delete'):
            menu()
        elif (len(sys.argv) > 1 and sys.argv[2] == '--delete'):
            project = sys.argv[1]
            print("Deleting all "+project+" project indexes")
            pattern = r'^[a-zA-Z0-9]+$'
            if re.match(pattern, project):
                deleteProject(project)
            print("Deleting all folders and files about "+project)
            print("Create a new project with this command: " + "\n")
            print("sh "+os.getcwd()+"/initProject.sh "+project+ "\n")
        elif (len(sys.argv) > 2):
            menu()
        elif (sys.argv[1] == '--help' or sys.argv[1] == '-h' or sys.argv[2] == '--help' or sys.argv[2] == '-h'):
            menu()
        else:
            print("An error occurred during c4mund0n60 execution \n")
            menu()
    except:
        menu()

if __name__== '__main__':
    main()