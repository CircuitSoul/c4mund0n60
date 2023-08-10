#!/usr/bin/env python3
import requests
from os import environ
import os
import sys
import json

def main(domain, apikey):
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
    params = {'apikey':apikey,'domain':domain}
    try:
        response = requests.get(url, params=params)
        jdata = response.json()
        domains = sorted(jdata['subdomains'])
    except(KeyError):
        print("No domains found for %s" % domain)
        exit(0)
    except(requests.ConnectionError):
        print("Could not connect to www.virtustotal.com", file=sys.stderr)
        exit(1)

    for domain in domains:
        print(domain)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python3 vt-subdomains.py domain.com VTAPIKEY", file=sys.stderr)
        sys.exit(1)
    domain = sys.argv[1]
    apikey = sys.argv[2]
    
    main(domain, apikey)
