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
version = float(re.search("(\d+.\d+)", ver.__version__).group(1))

import splunk.appserver.mrsparkle.lib.util as splunk_lib_util

try:
	from configparser import ConfigParser
except ImportError:
	from ConfigParser import ConfigParser

	

def get_logger(logger_id):
	log_path = splunk_lib_util.make_splunkhome_path(["var", "log", "splunk","TA-wifi1"])
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
	"""f_read = open(local_conf, "r")
	for line in f_read:
		if "token" in line:
			token = line.split("=")[1].strip()
		elif "sub" in line:
			global sub
			sub = line.split("=")[1].strip()
	f_read.close()
	response = ""
	url = "https://ipinfo.io/"+ip_add+"/privacy"
	param = {"token" : token}
        try:
	        response = requests.request("GET", url, headers="", params=param)
        	response_result = json.loads(response.text)
        except Exception as e:
                logger.info(e)"""


	config = ConfigParser()
	config.read(local_conf)
	url = config.get("ip_info_configuration","api_url")
	token = config.get("ip_info_configuration","api_token")
	enable = config.get("ip_info_configuration","proxy_enable")
	proxy_url = config.get("ip_info_configuration","proxy_url")
	response = ""
	url = "https://ipinfo.io/"+ip_add+"/privacy"
	param = {"token" : token}
	try:
		if enable == "No":
			response = requests.request("GET", url, headers="", params=param)
			response_result = json.loads(response.text)
		else:
            proxies = { 'https' : proxy_url}
			response = requests.request("GET", url, headers="", params=param, proxies=proxies)
			response_result = json.loads(response.text)
	except Exception as e:
		logger.info(e)


	result={}
	
	result["ip"] = ip_add
	result["vpn"] = response_result["vpn"] if 'vpn' in response_result else ""
	result["proxy"] = response_result["proxy"] if 'proxy' in response_result else ""
	result["tor"] = response_result["tor"] if 'tor' in response_result else ""
	result["hosting"] = response_result["hosting"] if 'hosting' in response_result else ""
	return result

def append_dict_as_row(file_name, dict_of_elem):
	# Open file in append mode
	field_names = ['time','ip','vpn','proxy','tor','hosting']
	with open(file_name, 'a+') as write_obj:
		# Create a writer object from csv module
		dict_writer = csv.DictWriter(write_obj, fieldnames=field_names)
		# Add dictionary as wor in the csv
		dict_writer.writerow(dict_of_elem)


def main():
        if len(sys.argv) != 2:
		print("Usage: python external_lookup.py [ip field]")
		sys.exit(1)

	privacy_info_csv = {}
	lookup_csv = splunk_lib_util.make_splunkhome_path(["etc","apps","ipinfo_app","lookups", "privacy_info.csv"])
    
	with open(lookup_csv, 'r') as file:
		csv_file = csv.DictReader(file)
		for row in csv_file:
			privacy_info_csv[row["ip"]]=row
			
	ipfield = sys.argv[1]
	infile = sys.stdin
	outfile = sys.stdout
	r = csv.DictReader(infile)
	header = r.fieldnames
	w = csv.DictWriter(outfile, fieldnames=r.fieldnames)
	w.writeheader()
	try:
        	for result in r:
	        	if result[ipfield]:
		        	
			        if(privacy_info_csv.has_key(result[ipfield])):
				        privacy_info_csv_record=privacy_info_csv[result[ipfield]];
        				result["ip"] = privacy_info_csv_record["ip"]
	        			result["vpn"] = privacy_info_csv_record["vpn"] if 'vpn' in privacy_info_csv_record else ""
		        		result["proxy"] = privacy_info_csv_record["proxy"] if 'proxy' in privacy_info_csv_record else ""
			        	result["tor"] = privacy_info_csv_record["tor"] if 'tor' in privacy_info_csv_record else ""
				        result["hosting"] = privacy_info_csv_record["hosting"] if 'hosting' in privacy_info_csv_record else ""
	        		else:
		        		return_response = ipinfo(result[ipfield])
			        	result["ip"] = return_response["ip"]
				        result["vpn"] = return_response["vpn"]
        				result["proxy"] = return_response["proxy"]
	        			result["tor"] = return_response["tor"]
		        		result["hosting"] = return_response["hosting"]
			        	return_response["time"] = time.time()
				        privacy_info_csv[result["ip"]]=return_response
        				append_dict_as_row(lookup_csv,return_response)
		        	w.writerow(result)
        except Exception as e:
                logger.error(e)        
		
main() 
