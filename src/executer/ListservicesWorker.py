from PyQt5.QtCore import QObject, pyqtSignal
from executer.grpcprotoclient import grpcprotoclient
from executer.grpcreflectionclient import grpcreflectionclient
from constants import *

class ListservicesWorker(QObject):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, host, creds, proto_path = None, proto_import_path = None):
        super().__init__()
        self.host = host
        self.creds = creds
        self.proto_path = proto_path
        self.proto_import_path = proto_import_path

    def run(self):
        try:
            response = {'error' : True, 'data' : None}
            if not self.host:
                response['data'] = 'Host is required'
                return response
            
            response = {'error' : True, 'data' : None}
        
            services = {}
            if (self.proto_path is not None or self.proto_import_path is not None):
                grpcprotoclient_instance = grpcprotoclient(self.proto_path, self.proto_import_path, self.host, self.creds)
                services = grpcprotoclient_instance.get_service_details()
            else:
                if not self.host:
                    response['data'] = 'Host is required'
                    return response
                
                grpcreflectionclient_instance = grpcreflectionclient(self.host, self.creds)
                services = grpcreflectionclient_instance.get_service_details()

            if ('success' in services and services['success'] == False):
                response = {'error' : True, 'data' : services}
            else:
                response = {'error' : False, 'data' : services}
            self.finished.emit(response)
            
        except Exception as e:
            self.helpercls.log('ListservicesWorker', {'inputData' : {self.proto_path, self.proto_import_path, self.host, self.creds}}, {'response' : response}, exception = e)
            self.error.emit(str(e))



# def get_services(self, proto_path = None, proto_import_path = None):
#         try:
#             response = {'error' : True, 'data' : None}
        
#             services = {}
#             if (proto_path is not None or proto_import_path is not None):
#                 grpcprotoclient_instance = grpcprotoclient(proto_path, proto_import_path, self.host, self.creds)
#                 services = grpcprotoclient_instance.get_service_details()
#             else:
#                 if not self.host:
#                     response['data'] = 'Host is required'
#                     return response
                
#                 grpcreflectionclient_instance = grpcreflectionclient(self.host, self.creds)
#                 services = grpcreflectionclient_instance.get_service_details()

#             if ('success' in services and services['success'] == False):
#                 response = {'error' : True, 'data' : services}
#             else:
#                 response = {'error' : False, 'data' : services}
            
#             return response
#         except Exception as e:
#             self.log('get_services', [proto_path, proto_import_path], exception=e)
    