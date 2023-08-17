import os
import time
import telegram
import sys
sys.path.append('helpers/configs')
from telegramBot import telegramNotification

# PARALLEL FUNCTIONS FOR SUBDOMAIN ENUMERATIONS
def parallel_subdomainTemp(target,domain):
    os.system('rm -rf targets/'+target+'/temp/subdomain_parallel_temp.log')
    
    with open ('targets/'+target+'/temp/subdomain_parallel_temp.log','a') as file:
        file.write('python3 helpers/parses/parse_assetfinder_temp.py '+target+' '+domain)
        file.write('python3 helpers/parses/parse_subfinder_temp.py '+target+' '+domain)
        file.write('python3 helpers/parses/parse_vtsubdomains_temp.py '+target+' '+domain)
        file.write('python3 helpers/parses/parse_chaos_temp.py '+target+' '+domain)
        file.write('python3 helpers/parses/parse_amass_temp.py '+target+' '+domain)
    message = "[+][+] PROCESSANDO SUBDOMAIN TEMP \n"
    print(message)
        
    try:
        os.system('cat targets/'+target+'/temp/subdomain_parallel_temp.log | parallel -u')
    except os.error as e:
        print("parallel_subdomainTemp error: ", e)
    
    return 1

# PARALLEL FUNCTIONS FOR PORT SCANNING
def parallel_rustscan(target,list_rustscan,dic_serv):
    os.system('rm -rf targets/'+target+'/temp/rustscan_parallel.log')
    for ip in list_rustscan:
        dic_serv[ip] = []
        with open ('targets/'+target+'/temp/rustscan_parallel.log','a') as file:
            file.write('python3 helpers/parses/parse_rustscan.py '+target+' '+ip+'\n')
    message = "[+] PROCESSANDO RUSTSCAN \n"
    print(message)
    
    try:
        os.system('cat targets/'+target+'/temp/rustscan_parallel.log | parallel -u')
    except os.error as e:
        print("parallel_rustscan error: ", e)
    
    return dic_serv

# PARALLEL FUNCTIONS FOR WEB ENUMERATIONS
def parallel_httpx(target,dic_subs_novos):
    os.system('rm -rf targets/'+target+'/temp/httpx_parallel.log')
    with open ('targets/'+target+'/temp/httpx_parallel.log','a') as file:
        for sub in dic_subs_novos:
            file.write('python3 helpers/parses/parse_httpx.py '+target+' '+sub+' '+dic_subs_novos[sub]+'\n')
    message = "[+] PROCESSANDO HTTPX \n"
    print(message)
        
    try:
        os.system('cat targets/'+target+'/temp/httpx_parallel.log | parallel -u')
    except os.error as e:
        print("parallel_httpx error: ", e)
    
    return 1

def parallel_waybackurls(target,dic_subs_novos_waybackurls):
    os.system('rm -rf targets/'+target+'/temp/waybackurls_parallel.log')
    with open ('targets/'+target+'/temp/waybackurls_parallel.log','a') as file:
        for sub in dic_subs_novos_waybackurls:
            file.write('python3 helpers/parses/parse_waybackurls.py '+target+' '+sub+' '+dic_subs_novos_waybackurls[sub][0]+' '+dic_subs_novos_waybackurls[sub][1]+'\n')
    message = "[+] PROCESSANDO WAYBACKURLS \n"
    print(message)
        
    try:
        os.system('cat targets/'+target+'/temp/waybackurls_parallel.log | parallel -u')
    except os.error as e:
        print("parallel_waybackurlsx error: ", e)
    
    return 1

def parallel_katana(target,dic_subs_novos_katana):   
    os.system('rm -rf targets/'+target+'/temp/katana_parallel.log')
    with open ('targets/'+target+'/temp/katana_parallel.log','a') as file:
        for sub in dic_subs_novos_katana:
            file.write('python3 helpers/parses/parse_katana.py '+target+' '+sub+' '+dic_subs_novos_katana[sub][0]+' '+dic_subs_novos_katana[sub][1]+'\n')
    message = "[+] PROCESSANDO KATANA \n"
    print(message)
        
    try:
        os.system('cat targets/'+target+'/temp/katana_parallel.log | parallel -u')
    except os.error as e:
        print("parallel_katana error: ", e)
    
    return 1


# PARALLEL FUNCTIONS FOR VULNERABITIES SCAN (WEB E INFRA)
def parallel_nuclei(target,dic_applications,dic_subs_novos):
    os.system('rm -rf targets/'+target+'/temp/nuclei_parallel.log')
    for sis in dic_applications:       
        if(sis.split(':')[1].split('/')[2] in dic_subs_novos):
            with open ('targets/'+target+'/temp/nuclei_parallel.log','a') as file:
                file.write('python3 helpers/parses/parse_nuclei.py '+target+' '+sis+' '+dic_applications[sis][0]+' '+dic_applications[sis][1]+' '+dic_applications[sis][2]+'\n')
    
    message = "[+] PROCESSANDO NUCLEI \n"
    print(message)
    
    try:
        os.system('cat targets/'+target+'/temp/nuclei_parallel.log | parallel -u')
    except os.error as e:
        print("parallel_nuclei error: ", e)

    return 1

