import splunk.Intersplunk
import requests
import json
import sys
import splunk.appserver.mrsparkle.lib.util as splunk_lib_util
import re
try:
    from configparser import ConfigParser
except ImportError:
    from ConfigParser import ConfigParser
import os


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
    f_read.close()"""
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
            return response.text
        else:
            proxies = { 'https' : proxy_url}
            response = requests.request("GET", url, headers="", verify= disable_ssl_request, params=param, proxies=proxies)
            return response.text
    except Exception as e:
        print(e)

results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()

sub = ""

for result in results:
    json_data = json.loads(ipinfo(result[sys.argv[1]]))
    #fo = open("text.txt", "w")
    result["ip"] = json_data["ip"]
    result["city"] = json_data["city"] if 'city' in json_data else ""
    result["region"] = json_data["region"] if 'region' in json_data else ""
    result["country"] = json_data["country"] if 'country' in json_data else ""
    result["loc"] = json_data["loc"] if 'loc' in json_data else ""
    result["hostname"] = json_data["hostname"] if 'hostname' in json_data else ""
    result["postal"] = json_data["postal"] if 'postal' in json_data else ""
    result["org"] = json_data["org"] if 'org' in json_data else ""
    result["subscription"] = "basic"
    
    if 'asn' in json_data:
        result["asn_asn"] = json_data["asn"]["asn"] if 'asn' in json_data["asn"] else ""
        result["asn_name"] = json_data["asn"]["name"] if 'name' in json_data["asn"] else ""
        result["asn_domain"] = json_data["asn"]["domain"] if 'domain' in json_data["asn"] else ""
        result["asn_route"] = json_data["asn"]["route"] if 'route' in json_data["asn"] else ""
        result["asn_type"] = json_data["asn"]["type"] if 'type' in json_data["asn"] else ""
        result["subscription"] = "standard"
    else:
        result["asn_asn"] = ""
        result["asn_name"] = ""
        result["asn_domain"] = ""
        result["asn_route"] = ""
        result["asn_type"] = ""

    if 'company' in json_data:
        result["company_name"] = json_data["company"]["name"] if 'name' in json_data["company"] else ""
        result["company_domain"] = json_data["company"]["domain"] if 'domain' in json_data["company"] else ""
        result["company_type"] = json_data["company"]["type"] if 'type' in json_data["company"] else ""
        result["subscription"] = "pro"
    else:
        result["company_name"] = ""
        result["company_domain"] = ""
        result["company_type"] = ""
    
    if 'carrier' in json_data:
        result["carrier_name"] = json_data["carrier"]["name"] if 'name' in json_data["carrier"] else ""
        result["carrier_mcc"] = json_data["carrier"]["mcc"] if 'mcc' in json_data["carrier"] else ""
        result["carrier_mnc"] = json_data["carrier"]["mnc"] if 'mnc' in json_data["carrier"] else ""
    else:
        result["carrier_name"] = ""
        result["carrier_mcc"] = ""
        result["carrier_mnc"] = ""

splunk.Intersplunk.outputResults(results)
