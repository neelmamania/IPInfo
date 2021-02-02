
import splunk.Intersplunk
import requests
import json
import sys
import splunk.appserver.mrsparkle.lib.util as splunk_lib_util
import os

def ipinfo():
    local_conf = splunk_lib_util.make_splunkhome_path(["etc","apps","ipinfo_app","local", "ip_info_setup.conf"])
    
    f_read = open(local_conf, "r")
    
    for line in f_read:
        if "token" in line:
            token = line.split("=")[1].strip()
        elif "sub" in line:
            global sub
            sub = line.split("=")[1].strip()
    f_read.close()
    
    url = "https://ipinfo.io/batch?token="+token
    headers = {'Content-type': 'application/json'}
    data = '["197.94.71.228", "197.94.71.227"]'
    
    response = requests.request("POST", url, headers=headers , data=data )

    records = response.json()
    for key,value in records.items():
        record=value
        return record



results = ipinfo()

#settings = splunk.Intersplunk.getOrganizedResults()

print(results)
#splunk.Intersplunk.outputResults(results)
#dispatch( sys.argv, sys.stdin, sys.stdout, __name__)