#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Copyright (c) 2021 Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

What is this :
	This script read FMC system information an display them
'''
import json
import sys
import requests
import yaml
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from pprint import pprint, pformat
from pathlib import Path
from crayons import blue, green, white, red, yellow,magenta, cyan


def yaml_load(filename):
	fh = open(filename, "r")
	yamlrawtext = fh.read()
	yamldata = yaml.load(yamlrawtext)
	return yamldata
 
if __name__ == "__main__":
	FMC_Server = {}
	FMC_Server = yaml_load("FMC_profile.yml")
	print()
	print(yellow("Get system information of FMC Server  :", bold=True))
	pprint(FMC_Server["FMC_Server"])	
	#pprint(FMC_Server["FMC_Server"][0]['ipaddr'])
	FMC_USER = FMC_Server["FMC_Server"][0]['username']
	FMC_PASSWORD = FMC_Server["FMC_Server"][0]['password']
	FMC_IPADDR = FMC_Server["FMC_Server"][0]['ipaddr']
	FMC_PORT = FMC_Server["FMC_Server"][0]['port']
	FMC_VERSION = FMC_Server["FMC_Server"][0]['version']
	print()
	server = "https://"+FMC_IPADDR+':'+str(FMC_PORT)

	line_content = []
	with open('token.txt') as inputfile:
		for line in inputfile:
			if line.strip()!="":	
				line_content.append(line.strip())
				
	auth_token = line_content[0]
	DOMAIN_UUID = line_content[1]	
			
	print ('auth_token :',auth_token)
	print ('UUID : ',DOMAIN_UUID)
	
	r = None

	headers = {'Content-Type': 'application/json'} 
	headers['X-auth-access-token']=auth_token
	 
	api_path = "/api/fmc_platform/v"+str(FMC_VERSION)+"/info/serverversion";    # param
	url = server + api_path
	if (url[-1] == '/'):
	    url = url[:-1]
	try:
	    # REST call with SSL verification turned off: 
	    r = requests.get(url, headers=headers, verify=False)
	    # REST call with SSL verification turned on:
	    # r = requests.post(url, data=json.dumps(post_data), headers=headers, verify='/path/to/ssl_certificate')
	    status_code = r.status_code
	    resp = r.text
	    print("Status code is: "+str(status_code))
	    if status_code == 200:
	        print ("Get was successful...")
	        json_resp = json.loads(resp)
	        print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
	    else :
	        r.raise_for_status()
	        print ("Error occurred in Get --> "+resp)
	except requests.exceptions.HTTPError as err:
	    print ("Error in connection --> "+str(err))
	finally:
	    if r: r.close()

