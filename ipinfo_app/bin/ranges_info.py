#!/usr/bin/env python

import csv
import sys
import socket
import time

import json
import requests
from requests import Request
import re
from splunk.clilib import cli_common as cli
import os
import logging
from logging.handlers import RotatingFileHandler
import splunk.version as ver
import datetime

maxbytes = 20000

if sys.version_info[0] >= 3:
        unicode = str

import splunk.appserver.mrsparkle.lib.util as splunk_lib_util

try:
	from configparser import ConfigParser
except ImportError:
	from ConfigParser import ConfigParser



def get_logger(logger_id):
	log_path = splunk_lib_util.make_splunkhome_path(["var", "log", "splunk","ipinfo"])
	if not (os.path.isdir(log_path)):
		os.makedirs(log_path)
		
	handler = RotatingFileHandler(log_path + '/ta-wifi.log', maxBytes = maxbytes,backupCount = 20)
	
	formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
	handler.setFormatter(formatter)
	logger = logging.getLogger(logger_id)
	logger.setLevel(logging.DEBUG)
	logger.addHandler(handler)
	return logger


logger = get_logger("TA-WiFi1")


sub = ""


def ipinfo(ip_add):

	local_conf = splunk_lib_util.make_splunkhome_path(["etc","apps","ipinfo_app","local", "ip_info_setup.conf"])
	default_conf = splunk_lib_util.make_splunkhome_path(["etc","apps","ipinfo_app","default", "ip_info_setup.conf"])
	config = ConfigParser()
	config.read([default_conf,local_conf])
	url = config.get("ip_info_configuration","api_url")
	token = config.get("ip_info_configuration","api_token")
	enable = config.get("ip_info_configuration","proxy_enable")
	proxy_url = config.get("ip_info_configuration","proxy_url")

	disable_ssl = config.get("ip_info_configuration","disable_ssl")
	cert_path=splunk_lib_util.make_splunkhome_path(["etc", "apps", "ipinfo_app","appserver","static","ipinfo.cert"])
	if (os.path.exists(cert_path)):
		cert_exists = True
	else:
		cert_exists = False

	if(disable_ssl != ""):
		disable_ssl_request=False
	else:
		disable_ssl_request=True

	if(disable_ssl_request==True and cert_exists==True):
		disable_ssl_request = cert_path


	response = ""
	url = "https://ipinfo.io/ranges/"+ip_add
	param = {"token" : token}
	try:
		if enable == "No":
			response = requests.request("GET", url, headers="", verify= disable_ssl_request, params=param)
			response_result = json.loads(response.text)
		else:
			proxies = { 'https' : proxy_url }
			response=requests.request("GET", url, headers="", verify= disable_ssl_request, params=param, proxies=proxies)
			response_result = json.loads(response.text)
	except Exception as e:
		logger.info(e)


	result={}
	str=","
	result["domain"] = ip_add
	result["num_ranges"] = response_result["num_ranges"] if 'num_ranges' in response_result else ""
	result["ranges"] = unicode(str.join(response_result["ranges"])).encode('ascii') if 'ranges' in response_result else ""
	return result



def main():
	if len(sys.argv) != 2:
		print("Usage: python external_lookup.py [ip field]")
		sys.exit(1)

			
	ipfield = sys.argv[1]
	infile = sys.stdin
	outfile = sys.stdout
	r = csv.DictReader(infile)
	w = csv.DictWriter(outfile, fieldnames=r.fieldnames)
	w.writeheader()
	try:
		for result in r:
			if result[ipfield]:
				return_response = ipinfo(result[ipfield])
				result["domain"] = return_response["domain"]
				result["num_ranges"] = return_response["num_ranges"]
				result["ranges"] = return_response["ranges"]  if 'ranges' in return_response else ""
				w.writerow(result)
	except Exception as e:
		logger.error(e)        
		
main() 
