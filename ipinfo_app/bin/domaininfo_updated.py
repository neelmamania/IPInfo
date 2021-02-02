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

if sys.version_info[0] >= 3:
        unicode = str


maxbytes = 20000
def get_logger(logger_id):
	log_path = splunk_lib_util.make_splunkhome_path(["var", "log", "splunk","ipinfo"])
	if not (os.path.isdir(log_path)):
		os.makedirs(log_path)
		
	handler = RotatingFileHandler(log_path + '/domaininfo.log', maxBytes = maxbytes,backupCount = 20)
	
	formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
	handler.setFormatter(formatter)
	logger = logging.getLogger(logger_id)
	logger.setLevel(logging.ERROR)
	logger.addHandler(handler)
	return logger

logger = get_logger("DomainInfo")

collection_name = "domaininfolookup"
@Configuration(local=True)
class ExtractDicom(StreamingCommand):
    def stream(self, records):

        domain_field = self.fieldnames[0]
        collection = self.service.kvstore[collection_name]
        for record in records:
            domain_value = record.get(domain_field)
            if domain_value != "":
                logger.debug("Checking Entry in KV store lookup")
                response = collection.data.query(query = json.dumps({"_key":domain_value}))
                logger.debug(response)
                try:
                    if(len(response)>0):
                        response[0].pop('time')
                        record.update(response[0])
                    else:
                        response = domaininfo(domain_value)
                        if bool(response):    
                            collection.data.insert(json.dumps(response))
                            response.pop('time')
                            record.update(response)
                except Exception as e:
                    logger.error(domain_value)
                    logger.error(e)
            yield record


def domaininfo(domain):

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
    url = "https://ipinfo.io/domains/"+domain
    param = {"token" : token}
    try:
        if enable == "No":
            response = requests.request("GET", url, headers="", verify= disable_ssl_request, params=param)
        else:
            proxies = { 'https' : proxy_url}
            response = requests.request("GET", url, headers="", verify= disable_ssl_request, params=param, proxies=proxies)
    except Exception as e:
        print(e)

    json_data = json.loads(response.text)
    result = {}
    if response.status_code == 200:
        if json_data.get("total") > 0:
            s=","
            result["ip"] = json_data["ip"]
            result["total"] = json_data["total"] if 'total' in json_data else ""
            domain_temp = str(unicode(s.join(json_data["domains"])).encode('ascii'))[2:] if 'domains' in json_data else ""
            result["domains"] = domain_temp[:-1]
            result["time"] = time.time()
            result["_key"] = json_data["ip"]
        else:
            logger.info("Response From Ipinfo :" + response.text )
    else:
        logger.error("Response Code : "+str(response.status_code) + "Response : " + response.text)
    return result


if __name__ == "__main__":
    dispatch(ExtractDicom, sys.argv, sys.stdin, sys.stdout, __name__)