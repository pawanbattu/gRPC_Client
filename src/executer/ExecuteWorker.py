from PyQt5.QtCore import QObject, pyqtSignal
from executer.grpcprotoclient import grpcprotoclient
from executer.grpcreflectionclient import grpcreflectionclient
from executer.helper import helper
import json
from constants import *

class ExecuteWorker(QObject):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, host, creds, proto_path, proto_import_path, meta_data, service_name, method_name, request_data, auth_data):
        super().__init__()
        self.host = host
        self.creds = creds
        self.proto_path = proto_path
        self.proto_import_path = proto_import_path
        self.meta_data = meta_data
        self.service_name = service_name
        self.method_name = method_name
        self.request_data = request_data
        self.auth_data = auth_data
        self.helpercls = helper()

    def run(self):
        try:
            response = {'error' : True, 'data' : None}
            if not self.host:
                response['data'] = 'Host is required'
                return response
            
            if not self.service_name:
                response['data'] = 'Please choose the service'
                return response    

            if not self.request_data:
                response['data'] = 'Please fill the request'
                return response 
            helpercls = helper()
            converted_meta_data = []
            if (self.meta_data):
                if (self.auth_data and isinstance(self.auth_data, dict) and len(self.auth_data) > 0):
                    auth_data_response = helpercls.convert_auth(self.auth_data)
                
                    if ('data' in auth_data_response and isinstance(auth_data_response['data'], tuple)):
                        converted_meta_data.append(auth_data_response['data'])
                    
                for data in self.meta_data:
                    if (('key' in data and 'value' in data) and (data['key'] and data['value'])):
                        converted_meta_data.append(tuple([data['key'], data['value']]))

            if not isinstance(self.request_data, dict):
                self.request_data = json.loads(self.request_data)
            
            if (self.proto_path or self.proto_import_path):
                grpcprotoclient_instance = grpcprotoclient(self.proto_path, self.proto_import_path, self.host, self.creds)
                res = grpcprotoclient_instance.validate_execute_request(self.service_name, self.method_name, self.request_data, converted_meta_data)
            else:
                grpcreflectionclient_instance = grpcreflectionclient(self.host, self.creds)
                res = grpcreflectionclient_instance.validate_execute_request(self.service_name, self.method_name, self.request_data, converted_meta_data)
            
            if (res):
                response = {'error' : True, 'data' : res}
            self.finished.emit(response)
            
        except Exception as e:
            self.helpercls.log('run', {'inputData' : {self.proto_path, self.proto_import_path, self.host, self.creds, self.service_name, self.method_name, self.request_data, converted_meta_data}}, {'response' : response}, exception = e)
            self.error.emit(str(e))
