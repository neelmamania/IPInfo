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
		
	handler = RotatingFileHandler(log_path + '/rangeinfo.log', maxBytes = maxbytes,backupCount = 20)
	
	formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
	handler.setFormatter(formatter)
	logger = logging.getLogger(logger_id)
	logger.setLevel(logging.ERROR)
	logger.addHandler(handler)
	return logger

logger = get_logger("Rangeinfo")

collection_name = "rangeinfolookup"
@Configuration(local=True)
class ExtractDicom(StreamingCommand):
    def stream(self, records):

        range_field = self.fieldnames[0]
        collection = self.service.kvstore[collection_name]
        for record in records:
            range_value = record.get(range_field)
            if range_value != "":
                logger.debug("Checking Entry in KV store lookup")
                response = collection.data.query(query = json.dumps({"_key":range_value}))
                logger.debug(response)
                try:
                    if(len(response)>0):
                        response[0].pop('time')
                        record.update(response[0])
                    else:
                        response = rangeinfo(range_value)
                        if bool(response):   
                            try:
                                collection.data.insert(json.dumps(response))
                            except Exception as e:
                                logger.error(e)
                            response.pop('time')
                            record.update(response)
                            logger.info(record)
                except Exception as e:
                    logger.error(range_value)
                    logger.error(e)
            yield record


def rangeinfo(range_value):

    local_conf = splunk_lib_util.make_splunkhome_path(["etc","apps","ipinfo_app","local", "ip_info_setup.conf"])
    default_conf = splunk_lib_util.make_splunkhome_path(["etc","apps","ipinfo_app","default", "ip_info_setup.conf"])
    config = ConfigParser()
    config.read([default_conf,local_conf])
    url = config.get("ip_info_configuration","api_url")
    token = config.get("ip_info_configuration","api_token")
    enable = config.get("ip_info_configuration","proxy_enable")
    proxy_url = config.get("ip_info_configuration","proxy_url")
    response = ""
    url = "https://ipinfo.io/ranges/"+range_value
    param = {"token" : token}
    try:
        if enable == "No":
            response = requests.request("GET", url, headers="", params=param)
        else:
            proxies = { 'https' : proxy_url }
            response=requests.request("GET", url, headers="", params=param, proxies=proxies)
    except Exception as e:
        print(e)

    json_data = json.loads(response.text)
    result = {}
    if response.status_code == 200:
        if len(json_data.get("ranges")) > 0:
            s=","
            result["domain"] = json_data["domain"]
            result["num_ranges"] = json_data["num_ranges"] if 'num_ranges' in json_data else ""
            temp_range = str(unicode(s.join(json_data["ranges"])).encode('ascii'))[2:] if 'ranges' in json_data else ""
            result["ranges"] = temp_range[:-1]
            result["time"] = time.time()
            result["_key"] = json_data["domain"]
        else:
            logger.info("Response From Ipinfo :" + response.text )
    else:
        logger.error("Response Code : "+str(response.status_code) + "Response : " + response.text)
    return result


if __name__ == "__main__":
    dispatch(ExtractDicom, sys.argv, sys.stdin, sys.stdout, __name__)