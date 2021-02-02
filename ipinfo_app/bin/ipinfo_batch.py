#!/usr/bin/env python
# Splunk specific dependencies
import sys, os
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators, splunklib_logger as logger
# Command specific dependencies
import requests
import json
import splunk.appserver.mrsparkle.lib.util as splunk_lib_util
import re
try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser

@Configuration(type='reporting')
class ipinfo(GeneratingCommand):

    url        = Option(require=False, validate=validators.Match('https url', '^https:\/\/'))
    headers    = Option(require=False)
    method     = Option(require=False, default='POST')
    ip         = Option(require=True)

  

    def generate(self):
        url        = "https://ipinfo.io/batch?token="
        headers    = self.parseHeaders("{'Content-type': 'application/json'}")
        method = "post"
        data = self.parseData(self.ip)

        record = {}

        storage_passwords=self.service.storage_passwords

        local_conf = splunk_lib_util.make_splunkhome_path(["etc","apps","ipinfo_app","local", "ip_info_setup.conf"])
    
        """f_read = open(local_conf, "r")

        for line in f_read:
            if "token" in line:
                token = line.split("=")[1].strip()
            elif "sub" in line:
                global sub
                sub = line.split("=")[1].strip()
        f_read.close()"""

        config = ConfigParser()
        config.read(local_conf)
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
        param = {"token" : token}
        try:
            if enable == "No":
                response = requests.request("post", url+token, headers=headers, verify= disable_ssl_request, data=data)
            else:
                proxies = { 'https' : proxy_url}
                response = requests.request("post", url+token, headers=headers, verify= disable_ssl_request, data=data, proxies=proxies)
        except Exception as e:
            logger.info(e)

        #url = url+token

        #response = requests.request(method, url, headers=headers , data=data )
        records = response.json()
        for key,value in records.items():
            record=value
            yield record
    
    def parseHeaders(self, headers):
    # Replace single quotes with double quotes for valid json
        return json.loads(
            headers.replace('\'', '"')
        )

    def parseData(self, data):
        data="[\""+data+"\"]"
        return (
            data.replace(',', '","') 
        )


dispatch(ipinfo, sys.argv, sys.stdin, sys.stdout, __name__)
