import os
import sys
import json
import grpc
import importlib
import subprocess
import importlib.util
import re
from datetime import datetime
from executer.grpcprotoclient import grpcprotoclient
from executer.grpcreflectionclient import grpcreflectionclient
from executer.helper import helper
from database.queries import queries
from constants import *

class main(queries):
    def __init__(self, host, creds = {}):
        super().__init__()
        self.host = host
        if not isinstance(creds, dict):
            self.creds = {}
        else:
            self.creds = creds
    

    def get_services(self, proto_path = None, proto_import_path = None):
        try:
            response = {'error' : True, 'data' : None}
        
            services = {}
            if (proto_path is not None or proto_import_path is not None):
                grpcprotoclient_instance = grpcprotoclient(proto_path, proto_import_path, self.host, self.creds)
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
            
            return response
        except Exception as e:
            self.log('get_services', [proto_path, proto_import_path], exception=e)
            


    def get_message_auto_populate(self, proto_path, proto_import_path, service_name, method_name):
        try:
            response = {'error' : True, 'data' : None}
            if not self.host:
                response['data'] = 'Host is required'
                return response
            
            if not method_name:
                response['data'] = 'Empty method is not passed'
                return response    
            
            if not service_name:
                response['data'] = 'Empty service name is not passed'
                return response    
            
            template = {}
            
            if (proto_path or proto_import_path):
                grpcprotoclient_instance = grpcprotoclient(proto_path, proto_import_path, self.host, self.creds)
                template = grpcprotoclient_instance.get_template_from_method_name(method_name)
            else:
                grpcreflectionclient_instance = grpcreflectionclient(self.host, self.creds)
                template = grpcreflectionclient_instance.get_template_from_method_name(service_name, method_name)
            
            if template:
                response = {'error' : False, 'data' : template}
            else:
                response = {'error' : False, 'data' : 'No data available'}
            return response
        except Exception as e:
            self.log('get_message_auto_populate', [proto_path, proto_import_path, service_name, method_name], exception=e)


    def execute_request(self, proto_path, proto_import_path, meta_data, service_name, method_name, request_data, auth_data):
        try:
            response = {'error' : True, 'data' : None}
            if not self.host:
                response['data'] = 'Host is required'
                return response
            
            if not service_name:
                response['data'] = 'Please choose the service'
                return response    

            if not request_data:
                response['data'] = 'Please fill the request'
                return response 
        
            converted_meta_data = []
            if (meta_data):
                if (auth_data and isinstance(auth_data, dict) and len(auth_data) > 0):
                    auth_data_response = self.convert_auth(auth_data)


                    if ('data' in auth_data_response and isinstance(auth_data_response['data'], tuple)):
                        converted_meta_data.append(auth_data_response['data'])
                        
                
                for data in meta_data:
                    if (('key' in data and 'value' in data) and (data['key'] and data['value'])):
                        converted_meta_data.append(tuple([data['key'], data['value']]))

            if not isinstance(request_data, dict):
                request_data = json.loads(request_data)
            
            if (proto_path or proto_import_path):
                grpcprotoclient_instance = grpcprotoclient(proto_path, proto_import_path, self.host, self.creds)
                response = grpcprotoclient_instance.validate_execute_request(service_name, method_name, request_data, converted_meta_data)
            else:
                grpcreflectionclient_instance = grpcreflectionclient(self.host, self.creds)
                response = grpcreflectionclient_instance.validate_execute_request(service_name, method_name, request_data, converted_meta_data)

            
            if (response):
                response = {'error' : True, 'data' : response}
            return response
        except Exception as e:
            self.log('execute_request', [proto_path, proto_import_path, meta_data, service_name, method_name, request_data, auth_data], exception=e)


    def is_json_serializable(self, obj):
        try:
            json.dumps(obj)
            return True
        except (TypeError, OverflowError) as e:
            self.log('is_json_serializable', [obj], exception=e)
        
    def insert_creds(self, creds):
        try:
            if (isinstance(creds, dict) and len(creds) > 0):
                self.insert_creds_entry(DEFAULT_TAB_ID, creds)
        except Exception as e:
            self.log('insert_creds', [creds], exception=e)
    
    def get_creds_db(self, where = {}):
        try:
            res = []
            data = self.get_creds(where)
            if (data):
                for key in data:
                    data_to_append = {}
                    data_to_append['client_certificate'] = key['client_certificate_crt']
                    data_to_append['client_key'] = key['client_key_file']
                    data_to_append['ca_certificate'] = key['ca_certificate_root_ca']
                    data_to_append['pem_certificate'] = key['pem_certificate']
                    data_to_append['host'] = key['host_name']
                    data_to_append['tab_id'] = key['tab_id']
                    data_to_append['env_id'] = key['env_id']
                    data_to_append['creds_id'] = key['id']
                    res.append(data_to_append)

            return res
        except Exception as e:
            self.log('get_creds_db', [where], exception=e)
    
    def save_tab_data(self, tab_name, method_name, data, request_data = "", env_id = "", tab_id = 0, collection_id = 0) :
        try:
            
            if (not isinstance(data, dict)):
                return False
            
            tab_data_to_insert = dict(
                tab_data={},
                meta_data=[],
                auth_data_list=[],
                creds_data = {}
                )

            tab_data_to_insert['tab_data']['tab_name'] = tab_name
            tab_data_to_insert['tab_data']['host_name'] = data.get('host', "")
            tab_data_to_insert['tab_data']['proto_file_path'] = data.get('proto_path', "")
            tab_data_to_insert['tab_data']['proto_additional_path'] = data.get('proto_import_path', "")
            tab_data_to_insert['tab_data']['method_name'] = method_name
            tab_data_to_insert['tab_data']['request_message'] = request_data
            tab_data_to_insert['tab_data']['env_id'] = env_id
            tab_data_to_insert['tab_data']['collection_id'] = collection_id

            if ('meta_data' in data):
                
                for key in data['meta_data']: 
                    if not isinstance(key , dict):
                        continue
                    meta_data = {}
                    meta_data['name'] = key.get('key', "")
                    meta_data['value'] = key.get('value', "")
                    meta_data['description'] = key.get('description', "")
                    meta_data['env_id'] = env_id
                    
                    tab_data_to_insert['meta_data'].append(meta_data)
                    
            
            if ('auth_data' in data):
                auth_data = {}
                auth_data['name'] = data['auth_data'].get("auth_type", '')

                data['auth_data'].pop("auth_type", None)
                json_str = ""
                
                if (isinstance(data['auth_data'], dict) and json.dumps(data['auth_data'])):
                    json_str = json.dumps(data['auth_data']) 
                auth_data['data'] = json_str

                tab_data_to_insert['auth_data_list'].append(auth_data)
                
            
            cur = self.insert_tab_transactional(tab_data_to_insert['tab_data'], tab_data_to_insert['creds_data'], tab_data_to_insert['meta_data'], tab_data_to_insert['auth_data_list'])

            if (cur and tab_id):
                self.delete_tab_transactional(tab_id)
            return cur
            
        except Exception as e:
            self.log('save_tab_data', [tab_name, method_name, data, request_data, env_id, tab_id], exception=e)

    def get_tabs_names(self):
        try:
            response = []
            data = self.get_all_tabs()
            if (data):
                response = data
            return response
        except Exception as e:
            self.log('get_tabs_names', [], exception=e)

    def delete_tab_id(self, tab_id):
        try:
            if (not id):
                return False
            
            data = self.delete_tab_transactional(tab_id)
            return data
        except Exception as e:
            self.log('delete_tab_id', [tab_id], exception=e)
