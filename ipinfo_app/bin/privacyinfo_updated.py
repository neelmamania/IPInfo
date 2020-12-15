import requests
import json
import sys
import splunk.appserver.mrsparkle.lib.util as splunk_lib_util
import re
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration
import time
import splunk.appserver.mrsparkle.lib.util as splunk_lib_util
import os
import logging
from logging.handlers import RotatingFileHandler

try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser



maxbytes = 20000
def get_logger(logger_id):
	log_path = splunk_lib_util.make_splunkhome_path(["var", "log", "splunk","ipinfo"])
	if not (os.path.isdir(log_path)):
		os.makedirs(log_path)
		
	handler = RotatingFileHandler(log_path + '/privacyinfo.log', maxBytes = maxbytes,backupCount = 20)
	
	formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
	handler.setFormatter(formatter)
	logger = logging.getLogger(logger_id)
	logger.setLevel(logging.ERROR)
	logger.addHandler(handler)
	return logger

logger = get_logger("PrivacyInfo")

collection_name = "privacyinfolookup"
@Configuration(local=True)
class ExtractDicom(StreamingCommand):
    def stream(self, records):

        privacy_field = self.fieldnames[0]
        collection = self.service.kvstore[collection_name]
        for record in records:
            privacy_value = record.get(privacy_field)
            if privacy_value != "":
                logger.debug("Checking Entry in KV store lookup")
                response = collection.data.query(query = json.dumps({"_key":privacy_value}))
                logger.debug(response)
                try:
                    if(len(response)>0):
                        response[0].pop('time')
                        record.update(response[0])
                    else:
                        response = privacyinfo(privacy_value)
                        if bool(response):    
                            collection.data.insert(json.dumps(response))
                            response.pop('time')
                            record.update(response)
                            logger.info(record)
                except Exception as e:
                    logger.error(privacy_value)
                    logger.error(e)
            yield record


def privacyinfo(privacy_value):

    local_conf = splunk_lib_util.make_splunkhome_path(["etc","apps","ipinfo_app","local", "ip_info_setup.conf"])
    default_conf = splunk_lib_util.make_splunkhome_path(["etc","apps","ipinfo_app","default", "ip_info_setup.conf"])
    config = ConfigParser()
    config.read([default_conf,local_conf])
    url = config.get("ip_info_configuration","api_url")
    token = config.get("ip_info_configuration","api_token")
    enable = config.get("ip_info_configuration","proxy_enable")
    proxy_url = config.get("ip_info_configuration","proxy_url")
    response = ""
    url = "https://ipinfo.io/"+privacy_value+"/privacy"
    param = {"token" : token}
    try:
        if enable == "No":
            response = requests.request("GET", url, headers="", params=param)
        else:
            proxies = { 'https' : proxy_url}
            response = requests.request("GET", url, headers="", params=param, proxies=proxies)
    except Exception as e:
        print(e)

    json_data = json.loads(response.text)
    result = {}
    if response.status_code == 200:
        if json_data.get("status") != 404:
            result["ip"] = privacy_value
            result["vpn"] = str(json_data["vpn"]) if 'vpn' in json_data else ""
            result["proxy"] = str(json_data["proxy"]) if 'proxy' in json_data else ""
            result["tor"] = str(json_data["tor"]) if 'tor' in json_data else ""
            result["hosting"] = str(json_data["hosting"]) if 'hosting' in json_data else ""
            result["time"] = time.time()
            result["_key"] = privacy_value
            logger.debug(result)
        else:
            logger.info("Response From Ipinfo :" + response.text )
    else:
        logger.error("Response Code : "+str(response.status_code) + "Response : " + response.text)
    return result


if __name__ == "__main__":
    dispatch(ExtractDicom, sys.argv, sys.stdin, sys.stdout, __name__)