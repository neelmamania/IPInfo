import splunk
import splunk.admin as admin
import splunk.entity as en
import os
import set_dashboards as dboard
import splunk.appserver.mrsparkle.lib.util as splunk_lib_util

class ConfigApp(admin.MConfigHandler):
    
    def setup(self):
        if self.requestedAction == admin.ACTION_EDIT:
            for arg in ['api_url', 'token', 'subscription']:
                self.supportedArgs.addOptArg(arg)
    
    def handleList(self, confInfo):
        confDict = self.readConf("ip_info_setup")
        if confDict is not None:
           configurations = confDict.get('api_configuration')
           for key, val in configurations.items():
               if key != 'subscription':
                  confInfo['api_configuration'].append(key, val)
                  
           confInfo["api_configuration"].append('subscription',confDict.get('api_configuration', {}).get('subscription', "Basic"))

    def handleEdit(self, confInfo):
        args = self.callerArgs.data
        for key, val in args.items():
            if val[0] is None:
                val[0] = ''
        
        api_url = args['api_url'][0]
        auth_token = args['token'][0]
        sub = args['subscription'][0]
        
        dboard.set_permission(sub)
        
        self.writeConf('ip_info_setup', 'api_configuration', self.callerArgs.data)
        
        splunk.rest.simpleRequest("/services/apps/local/_reload", self.getSessionKey(), postargs=None, method='POST', timeout=180)
        
# intialize the handler
admin.init(ConfigApp, admin.CONTEXT_NONE)