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

import splunk.appserver.mrsparkle.lib.util as splunk_lib_util

if sys.version_info[0] >= 3:
        unicode = str

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
	url = "https://ipinfo.io/"+ip_add
	param = {"token" : token}
	try:
		if enable == "No":
			response = requests.request("GET", url, headers="", verify= disable_ssl_request, params=param)
			response_result = json.loads(response.text)
		else:
			proxies = { 'https' : proxy_url}
			response = requests.request("GET", url, headers="", verify= disable_ssl_request, params=param, proxies=proxies)
			response_result = json.loads(response.text)
	except Exception as e:
		logger.info(e)
	result={}
	
	result["ip"] = response_result["ip"]
	result["city"] = response_result["city"] if 'city' in response_result else ""
	result["region"] = response_result["region"] if 'region' in response_result else ""
	result["country"] = response_result["country"] if 'country' in response_result else ""
	result["loc"] = response_result["loc"] if 'loc' in response_result else ""
	result["hostname"] = response_result["hostname"] if 'hostname' in response_result else ""
	result["postal"] = response_result["postal"] if 'postal' in response_result else ""
	result["org"] = response_result["org"] if 'org' in response_result else ""
	result["subscription"] = "basic"

	if 'asn' in response_result:
		result["asn_asn"] = response_result["asn"]["asn"] if 'asn' in response_result["asn"] else ""
		result["asn_name"] = response_result["asn"]["name"] if 'name' in response_result["asn"] else ""
		result["asn_domain"] = response_result["asn"]["domain"] if 'domain' in response_result["asn"] else ""
		result["asn_route"] = response_result["asn"]["route"] if 'route' in response_result["asn"] else ""
		result["asn_type"] = response_result["asn"]["type"] if 'type' in response_result["asn"] else ""
		result["subscription"] = "standard"
	else:
		result["asn_asn"] = ""
		result["asn_name"] = ""
		result["asn_domain"] = ""
		result["asn_route"] = ""
		result["asn_type"] = ""

	if 'company' in response_result:
		result["company_name"] = response_result["company"]["name"] if 'name' in response_result["company"] else ""
		result["company_domain"] = response_result["company"]["domain"] if 'domain' in response_result["company"] else ""
		result["company_type"] = response_result["company"]["type"] if 'type' in response_result["company"] else ""
		result["subscription"] = "pro"
	else:
		result["company_name"] = ""
		result["company_domain"] = ""
		result["company_type"] = ""

	if 'carrier' in response_result:
		result["carrier_name"] = response_result["carrier"]["name"] if 'name' in response_result["carrier"] else ""
		result["carrier_mcc"] = response_result["carrier"]["mcc"] if 'mcc' in response_result["carrier"] else ""
		result["carrier_mnc"] = response_result["carrier"]["mnc"] if 'mnc' in response_result["carrier"] else ""
	else:
		result["carrier_name"] = ""
		result["carrier_mcc"] = ""
		result["carrier_mnc"] = ""
	return result


def main():
	if len(sys.argv) != 2:
		print("Usage: python external_lookup.py [ip field]")
		sys.exit(1)

	#logger.info(ip_info_csv)	
	#logger.info(sys)
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
				result["ip"] = return_response["ip"]
				result["city"] = return_response["city"]
				result["region"] = return_response["region"]
				result["country"] = return_response["country"]
				result["loc"] = return_response["loc"]
				result["hostname"] = return_response["hostname"]
				result["postal"] = return_response["postal"]
				result["subscription"] = return_response["subscription"]
				result["org"] = return_response["org"]
				result["asn_asn"] = return_response["asn_asn"]
				result["asn_name"] = return_response["asn_name"]
				result["asn_domain"] = return_response["asn_domain"]
				result["asn_route"] = return_response["asn_route"]
				result["asn_type"] = return_response["asn_type"]
				result["company_name"] = return_response["company_name"]
				result["company_domain"] = return_response["company_domain"]
				result["company_type"] = return_response["company_type"]
				result["carrier_name"] = return_response["carrier_name"]
				result["carrier_mcc"] = return_response["carrier_mcc"]
				result["carrier_mnc"] = return_response["carrier_mnc"]
				w.writerow(result)
	except Exception as e:
		logger.error(e)      

main() 