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
        """
        f_read = open(local_conf, "r")
	for line in f_read:
		if "token" in line:
			token = line.split("=")[1].strip()
		elif "sub" in line:
			global sub
			sub = line.split("=")[1].strip()
	f_read.close()
        """
        config = ConfigParser()
        config.read(local_conf)
        url = config.get("ip_info_configuration","api_url")
        token = config.get("ip_info_configuration","api_token")
        enable = config.get("ip_info_configuration","proxy_enable")
        proxy_url = config.get("ip_info_configuration","proxy_url")
	response = ""
	url = "https://ipinfo.io/"+ip_add
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

def append_dict_as_row(file_name, dict_of_elem):
	# Open file in append mode
	field_names = ['time','ip','city','region','country','loc','hostname','postal','org','subscription','asn_asn','asn_name','asn_domain','asn_route','asn_type','company_name','company_domain','company_type','carrier_name','carrier_mcc','carrier_mnc']
	with open(file_name, 'a+') as write_obj:
		# Create a writer object from csv module
		dict_writer = csv.DictWriter(write_obj, fieldnames=field_names)
		# Add dictionary as wor in the csv
		dict_writer.writerow(dict_of_elem)


def main():
        if len(sys.argv) != 2:
		print("Usage: python external_lookup.py [ip field]")
		sys.exit(1)

	ip_info_csv = {}
	lookup_csv = splunk_lib_util.make_splunkhome_path(["etc","apps","ipinfo_app","lookups", "ip_info.csv"])
	field_names = ['time','ip','city','region','country','loc','hostname','postal','org','subscription','asn_asn','asn_name','asn_domain','asn_route','asn_type','company_name','company_domain','company_type','carrier_name','carrier_mcc','carrier_mnc']
	if(os.path.isfile(lookup_csv)):
        	logger.debug("file exists")
	else:
		try:
			with open(lookup_csv, 'w') as file:
				writer = csv.DictWriter(file, fieldnames=field_names)
				writer.writeheader()
		except Exception as e:
			logger.error(e)
    
	with open(lookup_csv, 'r') as file:
		csv_file = csv.DictReader(file)
		
		for row in csv_file:
			ip_info_csv[row["ip"]]=row
	#logger.info(ip_info_csv)	
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
		        	
			        if(ip_info_csv.has_key(result[ipfield])):
				        ip_info_csv_record=ip_info_csv[result[ipfield]];
        				result["ip"] = ip_info_csv_record["ip"]
	        			result["city"] = ip_info_csv_record["city"] if 'city' in ip_info_csv_record else ""
		        		result["region"] = ip_info_csv_record["region"] if 'region' in ip_info_csv_record else ""
			        	result["country"] = ip_info_csv_record["country"] if 'country' in ip_info_csv_record else ""
				        result["loc"] = ip_info_csv_record["loc"] if 'loc' in ip_info_csv_record else ""
        				result["hostname"] = ip_info_csv_record["hostname"] if 'hostname' in ip_info_csv_record else ""
	        			result["postal"] = ip_info_csv_record["postal"] if 'postal' in ip_info_csv_record else ""
		        		result["org"] = ip_info_csv_record["org"] if 'org' in ip_info_csv_record else ""
			        	result["subscription"] = ip_info_csv_record["subscription"] if 'subscription' in ip_info_csv_record else ""
        				result["asn_asn"] = ip_info_csv_record["asn_asn"] if 'asn_asn' in ip_info_csv_record else ""
	        			result["asn_name"] = ip_info_csv_record["asn_name"] if 'asn_name' in ip_info_csv_record else ""
		        		result["asn_domain"] = ip_info_csv_record["asn_domain"] if 'asn_domain' in ip_info_csv_record else ""
			        	result["asn_route"] = ip_info_csv_record["asn_route"] if 'asn_route' in ip_info_csv_record else ""
				        result["asn_type"] = ip_info_csv_record["asn_type"] if 'asn_type' in ip_info_csv_record else ""
                                        result["company_name"] = ip_info_csv_record["company_name"] if 'company_name' in ip_info_csv_record else ""
	        			result["company_domain"] = ip_info_csv_record["company_domain"] if 'company_domain' in ip_info_csv_record else ""
		        		result["company_type"] = ip_info_csv_record["company_type"] if 'company_type' in ip_info_csv_record else ""
                                        result["carrier_name"] = ip_info_csv_record["carrier_name"] if 'carrier_name' in ip_info_csv_record else ""
				        result["carrier_mcc"] = ip_info_csv_record["carrier_mcc"] if 'carrier_mcc' in ip_info_csv_record else ""
        				result["carrier_mnc"] = ip_info_csv_record["carrier_mnc"] if 'carrier_mnc' in ip_info_csv_record else ""
	        		else:
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
			        	return_response["time"] = time.time()
				        ip_info_csv[result["ip"]]=return_response
        				append_dict_as_row(lookup_csv,return_response)
		        	w.writerow(result)
        except Exception as e:
                logger.error(e)        
		
main() 
