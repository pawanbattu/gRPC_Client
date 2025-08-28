from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc
from google.protobuf.descriptor_pool import DescriptorPool
from google.protobuf.json_format import ParseDict, MessageToDict
import grpc
import json
import re
import grpc as grpcbase
from datetime import datetime, timezone
import base64
from executer.ProtobufStructureValidator import ProtobufStructureValidator
from executer.ProtobufConverter import ProtobufConverter
from executer.helper import helper
from google.protobuf.descriptor import Descriptor, FieldDescriptor
from google.protobuf import descriptor_pool
from google.protobuf import descriptor_pb2
from google.protobuf import message_factory

from google.protobuf.message_factory import GetMessageClass
from google.protobuf.message import Message
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.wrappers_pb2 import (
    StringValue, BoolValue, Int32Value, Int64Value,
    UInt32Value, UInt64Value, FloatValue, DoubleValue
)
from datetime import datetime
from typing import Dict, Any


class grpcreflectionclient(helper):

    def __init__(self, host, creds = {}):
        super().__init__()
        self.host = host
        self.creds = creds

        self.WELL_KNOWN_TYPE_TEMPLATES = {
            "google.protobuf.Timestamp": {"seconds": 0, "nanos": 0},
            "google.protobuf.Duration": {"seconds": 0, "nanos": 0},
            "google.protobuf.FieldMask": {"paths": []},
            "google.protobuf.Struct": {},
            "google.protobuf.Value": None,
            "google.protobuf.ListValue": [],
            "google.protobuf.NullValue": None,
            "google.protobuf.Any": {"@type": "", "value": ""},
            "google.protobuf.BoolValue": {"value": False},
            "google.protobuf.StringValue": {"value": ""},
            "google.protobuf.BytesValue": {"value": b""},
            "google.protobuf.Int32Value": {"value": 0},
            "google.protobuf.Int64Value": {"value": 0},
            "google.protobuf.UInt32Value": {"value": 0},
            "google.protobuf.UInt64Value": {"value": 0},
            "google.protobuf.FloatValue": {"value": 0.0},
            "google.protobuf.DoubleValue": {"value": 0.0},
            "google.protobuf.Api": {"name": "", "methods": [], "options": [], "version": ""},
            "google.protobuf.Method": {"name": "", "request_type_url": "", "request_streaming": False,
                                         "response_type_url": "", "response_streaming": False, "options": [], "syntax": 0},
            "google.protobuf.Mixin": {"name": "", "root": ""},
            "google.protobuf.Option": {"name": "", "value": None},
            "google.protobuf.SourceContext": {"file_name": ""},
            "google.protobuf.Enum": {"name": "", "value": [], "options": [], "reserved_range": [], "reserved_name": []},
            "google.protobuf.EnumValue": {"name": "", "number": 0, "options": []},
            "google.protobuf.Type": {"name": "", "fields": [], "oneofs": [], "options": [], "source_context": {},
                                      "syntax": 0},
            "google.protobuf.Field": {"kind": 0, "cardinality": 0, "number": 0, "name": "", "type_url": "", "oneof_index": 0,
                                        "packed": False, "options": [], "json_name": "", "default_value": ""},
        }
        self.pool = descriptor_pool.DescriptorPool()
        self.loaded_files = set()
        self.reflection_stub = None

    def list_reflection_services(self) -> list[str]:
        """
        Connects to a gRPC server and lists all available services via reflection.
        """
        try:
            services = []
            channel = self.connect_to_server()
            
            stub = reflection_pb2_grpc.ServerReflectionStub(channel)
            request = reflection_pb2.ServerReflectionRequest(list_services="")
            responses = stub.ServerReflectionInfo(iter([request]))
            if (responses):
                for resp in responses:
                    for s in resp.list_services_response.service:
                        services.append(s.name)
            return services
        except grpc.RpcError as e:
            self.log(function_name='list_reflection_services', args=[], exception=e)
            return self.exception_to_serializable(e)
        except Exception as e:
            self.log(function_name='list_reflection_services', args=[], exception=e)
            return self.exception_to_serializable(e)
        finally:
            self.close_server_connection(channel)


    def get_service_descriptor(self, service_name: str) -> descriptor_pb2.FileDescriptorProto:
        """
        Retrieves the FileDescriptorProto for a given service using reflection.
        """
        try:
            channel = self.connect_to_server()
            stub = reflection_pb2_grpc.ServerReflectionStub(channel)
            request = reflection_pb2.ServerReflectionRequest(file_containing_symbol=service_name)
            
            responses = stub.ServerReflectionInfo(iter([request]))
            for resp in responses:
                fd_response = resp.file_descriptor_response
                if fd_response.file_descriptor_proto:
                    fd_proto = descriptor_pb2.FileDescriptorProto()
                    fd_proto.ParseFromString(fd_response.file_descriptor_proto[0])
                    return fd_proto
            raise RuntimeError(f"Service descriptor for '{service_name}' not found")

        except Exception as e:
            self.log(function_name='get_service_descriptor', args=[service_name], exception=e)
            return self.exception_to_serializable(e)
        finally:
            self.close_server_connection(channel)


    def get_service_details(self): #, fd_proto: descriptor_pb2.FileDescriptorProto):
        try:
            data_to_return = {}
            services = self.list_reflection_services()
            if (services):
                for servicedata in services:
                    if re.match(servicedata, 'grpc.reflection.v1alpha.ServerReflection'): continue
                    service_list = { 
                        'full_name': "", 
                        "name": "", 
                        "methods": []
                        }
                    fd_proto = self.get_service_descriptor(servicedata)
                    for service in fd_proto.service:
                        # Set service name and full name (package.service_name)
                        service_list['name'] = service.name
                        if fd_proto.package:
                            service_list['full_name'] = f"{fd_proto.package}.{service.name}"
                        else:
                            service_list['full_name'] = service.name
                        
                        # Extract method details
                        for method in service.method:
                            # method_info = {
                            #     'name': method.name,
                            #     'input_type': method.input_type,
                            #     'output_type': method.output_type,
                            #     'client_streaming': method.client_streaming,
                            #     'server_streaming': method.server_streaming
                            # }
                            service_list['methods'].append(method.name)
                    data_to_return[servicedata] = service_list
                    
            return data_to_return
        except grpc.RpcError as e:
            self.log(function_name='get_service_details', args=[], exception=e)
            return self.exception_to_serializable(e)
        except Exception as e:
            self.log(function_name='get_service_details', args=[], exception=e)
            return self.exception_to_serializable(e)
    

    def get_dynamic_well_known_template(self, type_name: str):
            try:
                if type_name == "google.protobuf.Timestamp":
                    now = datetime.now(timezone.utc)
                    return {
                        "seconds": int(now.timestamp()),
                        "nanos": now.microsecond * 1000
                    }
                elif type_name == "google.protobuf.Any":
                    embedded_message = {"example_field": "value"}
                    return {
                        "@type": "type.googleapis.com/example.Message",
                        "value": base64.b64encode(json.dumps(embedded_message).encode()).decode()
                    }
                return self.WELL_KNOWN_TYPE_TEMPLATES.get(type_name)
            except Exception as e:
                self.log(function_name='get_dynamic_well_known_template', args=[type_name], exception=e)

    def _default_for_field(self, field, descriptor_pool, type_lookup):
        try:
            type_ = field.type
            type_name = field.type_name

            if type_ == descriptor_pb2.FieldDescriptorProto.TYPE_ENUM:
                enum_name = type_name.lstrip(".")
                enum_descriptor = type_lookup.get(enum_name)
                return enum_descriptor.value[0].name if enum_descriptor and enum_descriptor.value else "UNKNOWN_ENUM"

            elif type_ == descriptor_pb2.FieldDescriptorProto.TYPE_STRING:
                return ""

            elif type_ == descriptor_pb2.FieldDescriptorProto.TYPE_BYTES:
                return b""

            elif type_ in (
                descriptor_pb2.FieldDescriptorProto.TYPE_INT32,
                descriptor_pb2.FieldDescriptorProto.TYPE_INT64,
                descriptor_pb2.FieldDescriptorProto.TYPE_UINT32,
                descriptor_pb2.FieldDescriptorProto.TYPE_UINT64,
                descriptor_pb2.FieldDescriptorProto.TYPE_SINT32,
                descriptor_pb2.FieldDescriptorProto.TYPE_SINT64,
                descriptor_pb2.FieldDescriptorProto.TYPE_FIXED32,
                descriptor_pb2.FieldDescriptorProto.TYPE_FIXED64,
                descriptor_pb2.FieldDescriptorProto.TYPE_SFIXED32,
                descriptor_pb2.FieldDescriptorProto.TYPE_SFIXED64
            ):
                return 0

            elif type_ == descriptor_pb2.FieldDescriptorProto.TYPE_BOOL:
                return False

            elif type_ in (
                descriptor_pb2.FieldDescriptorProto.TYPE_FLOAT,
                descriptor_pb2.FieldDescriptorProto.TYPE_DOUBLE,
            ):
                return 0.0

            elif type_ == descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE:
                nested_name = type_name.lstrip(".")
                nested_descriptor = descriptor_pool.get(nested_name)
                if nested_descriptor:
                    return self.build_template_from_descriptor(nested_descriptor, descriptor_pool, type_lookup)
                elif nested_name in self.WELL_KNOWN_TYPE_TEMPLATES:
                    return self.get_dynamic_well_known_template(nested_name)
                else:
                    return {}

            elif type_ == descriptor_pb2.FieldDescriptorProto.TYPE_GROUP:
                return {}

            else:
                return "unknown_type"
        except Exception as e:
            self.log(function_name='_default_for_field', args=[field, descriptor_pool, type_lookup], exception=e)

    def build_template_from_descriptor(self, msg_descriptor, descriptor_pool, type_lookup, return_dict=True):
        try:
            template = {}

            map_fields = {
                field.name: field
                for field in msg_descriptor.field
                if field.type == descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE
                and descriptor_pool.get(field.type_name.lstrip("."), {}).options.map_entry
            }

            for field in msg_descriptor.field:
                name = field.name
                label = field.label
                type_ = field.type
                type_name = field.type_name
                is_repeated = (label == descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED)

                if name in map_fields:
                    entry_type = type_name.lstrip(".")
                    entry_descriptor = descriptor_pool.get(entry_type)
                    key_field = next((f for f in entry_descriptor.field if f.name == 'key'), None)
                    value_field = next((f for f in entry_descriptor.field if f.name == 'value'), None)
                    map_key = self._default_for_field(key_field, descriptor_pool, type_lookup)
                    map_value = self._default_for_field(value_field, descriptor_pool, type_lookup)
                    template[name] = {map_key: map_value}
                    continue

                value = self._default_for_field(field, descriptor_pool, type_lookup)

                if is_repeated:
                    template[name] = [value]
                else:
                    template[name] = value

            return template

        except Exception as e:
            self.log(function_name='build_template_from_descriptor', args=[msg_descriptor, descriptor_pool, type_lookup, return_dict], exception=e)
            return {}



    def extract_descriptor_pool(self, fd_proto: descriptor_pb2.FileDescriptorProto):
        try:
            descriptor_pool = {}

            def recurse(fdp):
                for msg in fdp.message_type:
                    full_name = f"{fdp.package}.{msg.name}" if fdp.package else msg.name
                    descriptor_pool[full_name] = msg
                    for nested in msg.nested_type:
                        descriptor_pool[f"{full_name}.{nested.name}"] = nested

            recurse(fd_proto)
            return descriptor_pool
        except Exception as e:
            self.log(function_name='extract_descriptor_pool', args=[fd_proto], exception=e)
            return self.exception_to_serializable(e)


    def get_template_for_method(self, fd_proto, method_name: str):
        try:
            descriptor_pool = self.extract_descriptor_pool(fd_proto)

            for service in fd_proto.service:
                for method in service.method:
                    if method.name == method_name:
                        input_type = method.input_type.lstrip(".")  # remove leading dot
                        msg_descriptor = descriptor_pool.get(input_type)
                        if not msg_descriptor:
                            raise ValueError(f"Message descriptor for {input_type} not found")
                        return self.build_template_from_descriptor(msg_descriptor, descriptor_pool)
            
            raise ValueError(f"Method '{method_name}' not found in service descriptors")
        except Exception as e:
            self.log(function_name='get_template_for_method', args=[fd_proto, method_name], exception=e)
            return self.exception_to_serializable(e)




    def get_all_descriptors(self, service_name: str):
        try:
            channel = self.connect_to_server()
            stub = reflection_pb2_grpc.ServerReflectionStub(channel)

            seen_files = set()
            descriptor_protos = []

            def fetch_file_and_deps(file_name):
                if file_name in seen_files:
                    return
                seen_files.add(file_name)
                req = reflection_pb2.ServerReflectionRequest(file_by_filename=file_name)
                responses = stub.ServerReflectionInfo(iter([req]))
                for resp in responses:
                    for fd_bytes in resp.file_descriptor_response.file_descriptor_proto:
                        fd_proto = descriptor_pb2.FileDescriptorProto()
                        fd_proto.ParseFromString(fd_bytes)
                        descriptor_protos.append(fd_proto)
                        for dep in fd_proto.dependency:
                            fetch_file_and_deps(dep)
                    break

            # Get entry point from symbol
            initial_req = reflection_pb2.ServerReflectionRequest(file_containing_symbol=service_name)
            initial_resp = next(stub.ServerReflectionInfo(iter([initial_req])))

            for fd_bytes in initial_resp.file_descriptor_response.file_descriptor_proto:
                fd_proto = descriptor_pb2.FileDescriptorProto()
                fd_proto.ParseFromString(fd_bytes)
                descriptor_protos.append(fd_proto)
                for dep in fd_proto.dependency:
                    fetch_file_and_deps(dep)

            return descriptor_protos
        except Exception as e:
            self.log(function_name='get_all_descriptors', args=[service_name], exception=e)
            return self.exception_to_serializable(e)
        finally:
            self.close_server_connection(channel)


    def merge_descriptor_pools(self, fd_protos):
        try:
            descriptor_pool = {}
            type_lookup = {}

            for fd in fd_protos:
                pkg = fd.package
                prefix = f"{pkg}." if pkg else ""
                for msg in fd.message_type:
                    descriptor_pool[f"{prefix}{msg.name}"] = msg
                    for nested in msg.nested_type:
                        descriptor_pool[f"{prefix}{msg.name}.{nested.name}"] = nested
                for enum in fd.enum_type:
                    type_lookup[f"{prefix}{enum.name}"] = enum

            return descriptor_pool, type_lookup
        except Exception as e:
            self.log(function_name='merge_descriptor_pools', args=[fd_protos], exception=e)
            return self.exception_to_serializable(e)
    
    def get_template_from_method_name(self, service_name, method_name):
        try:
            # 1. Fetch all protos
            fds = self.get_all_descriptors(service_name)

            # 2. Build merged descriptor pool
            descriptor_pool, type_lookup = self.merge_descriptor_pools(fds)

            for fd in fds:
                for svc in fd.service:
                    if svc.name == service_name.split(".")[-1]:
                        for method in svc.method:
                            if method.name == method_name:
                                msg_type = method.input_type.lstrip(".")
                                msg_desc = descriptor_pool.get(msg_type)
                                if not msg_desc:
                                    raise RuntimeError(f"Descriptor for {msg_type} not found")
                                template = self.build_template_from_descriptor(msg_desc, descriptor_pool, type_lookup)
                                return template
        except Exception as e:
            self.log(function_name='get_template_from_method_name', args=[service_name, method_name], exception=e)
            return self.exception_to_serializable(e)


    ##DO not use for now
    def list_all_services(self):
        try:
            data_to_return = {}
            services = self.list_reflection_services()
            
            if services:
                for service in services:
                    if re.match(service, 'grpc.reflection.v1alpha.ServerReflection'): continue
                    fd = self.get_service_descriptor(service)
                    data_to_return[service] = self.get_service_details(fd)
                    

            return data_to_return

        except Exception as e:
            self.log(function_name='list_all_services', args=[], exception=e)
            return self.exception_to_serializable(e)
    
    def connect_to_server(self):
        try:
            root_certificates = private_key = certificate_chain = None
            
            if (isinstance(self.creds, dict) and len(self.creds) == 0):
                channel = grpcbase.insecure_channel(self.host)
            else:
                if ('client_key' in self.creds and self.creds['client_key']):
                    with open(self.creds['client_key'], 'rb') as f:
                        private_key = f.read()
                        
                if ('client_certificate' in self.creds and self.creds['client_certificate']):
                    with open(self.creds['client_certificate'], 'rb') as f:
                        certificate_chain = f.read()
                        
                if ('ca_certificate' in self.creds and self.creds['ca_certificate']):
                    with open(self.creds['ca_certificate'], 'rb') as f:
                        root_certificates = f.read()
                        

                if ((private_key is not None and certificate_chain is None) or (private_key is None and certificate_chain is not None)):
                    raise("Both private and certificate_chain are required")
                
                if (root_certificates is not None):
                        # Create SSL channel credentials with client certificates
                        credentials = grpcbase.ssl_channel_credentials(
                            root_certificates=root_certificates,
                            private_key=private_key,
                            certificate_chain=certificate_chain
                        )
                else:
                    credentials = grpcbase.ssl_channel_credentials(
                            private_key=private_key,
                            certificate_chain=certificate_chain
                        )    

                channel = grpcbase.secure_channel(self.host, credentials)
                if channel is None:
                    result = {'error' : True, 'data' : "Could not connect to server"}
                    return result
            self.reflection_stub = reflection_pb2_grpc.ServerReflectionStub(channel)

            return channel
        except grpc.RpcError as e:
            self.log(function_name='connect_to_server', args=[], exception=e)
        except Exception as e:
            self.log(function_name='connect_to_server', args=[], exception=e)
            return self.exception_to_serializable(e)
        
    
    def close_server_connection(self, channel):
        try:
            if channel is not None or channel is not dict:
                channel.close()
        except Exception as e:
            
            return self.exception_to_serializable(e)

    def _extract_dependency_name(self, error_msg):
        try:
            """
            Robustly extracts the missing dependency filename from a TypeError message
            raised by descriptor_pool.Add().
            """
            # Prioritize regex for "Depends on file 'filename'" pattern
            match = re.search(r"Depends on file '(.+?)'", error_msg)
            if match:
                return match.group(1)

            # Fallback patterns for other potential formats
            patterns = [
                r"file '(.+\.proto)'",
                r"dependency '(.+\.proto)'"
            ]
            for pattern in patterns:
                match = re.search(pattern, error_msg)
                if match:
                    return match.group(1)

            # Last resort: try splitting by single quotes if a .proto extension is present
            if "'" in error_msg:
                parts = error_msg.split("'")
                if len(parts) >= 2 and '.proto' in parts[1]:
                    return parts[1]

            return None # No dependency name could be extracted
        except Exception as e:
            self.log(function_name='_extract_dependency_name', args=[error_msg], exception=e)

    def _add_file_descriptor_attempt(self, fd_proto_bytes):
        """
        Attempts to add a single file descriptor proto to the pool.
        Returns:
            True: if successfully added.
            False: if parsing or another non-dependency error occurred.
            str: the name of the missing dependency if a TypeError occurs.
        """
        fd = descriptor_pb2.FileDescriptorProto()
        try:
            fd.ParseFromString(fd_proto_bytes)
            file_name = fd.name
        except Exception as e:
            print(f"Failed to parse file descriptor bytes: {str(e)}")
            return False # Parsing failed

        if file_name in self.loaded_files:
            return True # Already loaded

        try:
            self.pool.Add(fd)
            self.loaded_files.add(file_name)

            return True # Successfully added
        except TypeError as e:
            error_msg = str(e)
            print(f"Descriptor error for {file_name}: {error_msg}")
            missing_dep = self._extract_dependency_name(error_msg)
            if not missing_dep:
                print(f"Could not determine missing dependency name from error for {file_name}.")
                return False # Cannot proceed without dependency name
            return missing_dep # Indicate missing dependency
        except Exception as e:
            self.log(function_name='_add_file_descriptor_attempt', args=[fd_proto_bytes], exception=e)
            return False # Other error

    def _try_add_file_descriptor_with_deps(self, fd_proto_list_bytes, reflection_stub):
        try:
            """
            Attempts to add a list of file descriptors, iteratively resolving
            dependencies by fetching them from the server using the provided reflection_stub.
            Returns True if all are added, False otherwise.
            """
            files_to_process = list(fd_proto_list_bytes)
            max_dependency_resolution_passes = 50 # Prevent infinite loops for unresolvable deps

            for pass_num in range(max_dependency_resolution_passes):
                
                if not files_to_process:
                    
                    return True # All files have been processed

                next_files_to_process = []
                newly_loaded_in_this_pass = False

                current_pass_files = list(files_to_process) # Copy for iteration
                files_to_process = [] # Reset for next pass

                for fd_proto_bytes in current_pass_files:
                    temp_fd = descriptor_pb2.FileDescriptorProto()
                    temp_fd.ParseFromString(fd_proto_bytes)
                    file_name = temp_fd.name

                    if file_name in self.loaded_files: # Already in pool from a previous pass
                        continue

                    
                    result = self._add_file_descriptor_attempt(fd_proto_bytes)

                    if result is True: # Successfully added
                        newly_loaded_in_this_pass = True
                    elif result is False: # Failed (parsing or other error)
                        print(f"Failed to add file {file_name} due to an internal error. Aborting.")
                        return False
                    else: # Missing dependency (result is the dependency name string)
                        missing_dep_name = result
                        print(f"File {file_name} needs dependency: {missing_dep_name}")

                        # If this dependency is not yet loaded, try to fetch it
                        if missing_dep_name not in self.loaded_files:
                            try:
                                print(f"Fetching missing dependency: {missing_dep_name}")
                                dep_request = reflection_pb2.ServerReflectionRequest(
                                    file_by_filename=missing_dep_name
                                )
                                dep_response = next(reflection_stub.ServerReflectionInfo(iter([dep_request])))

                                if dep_response.HasField('file_descriptor_response'):
                                    for dep_fd_bytes in dep_response.file_descriptor_response.file_descriptor_proto:
                                        temp_dep_fd = descriptor_pb2.FileDescriptorProto()
                                        temp_dep_fd.ParseFromString(dep_fd_bytes)
                                        # Add to next_files_to_process if not already queued or loaded
                                        if (temp_dep_fd.name not in self.loaded_files and
                                            temp_dep_fd.name not in [d.name for d in next_files_to_process if isinstance(d, bytes) and descriptor_pb2.FileDescriptorProto.FromString(d).name == temp_dep_fd.name]):
                                            next_files_to_process.append(dep_fd_bytes)
                                    print(f"Queued {len(dep_response.file_descriptor_response.file_descriptor_proto)} dependency files for {missing_dep_name}.")
                                else:
                                    print(f"Dependency {missing_dep_name} not available from server for {file_name}. Aborting.")
                                    return False # Dependency truly missing from server
                            except Exception as dep_error:
                                print(f"Failed to fetch dependency {missing_dep_name}: {str(dep_error)}. Aborting.")
                                return False # Error fetching dependency
                        else:
                            print(f"Dependency {missing_dep_name} already loaded for {file_name}.")

                        # Put the current file back to process in a future pass, as its dependency might now be available
                        next_files_to_process.append(fd_proto_bytes)

                files_to_process = next_files_to_process

                if not newly_loaded_in_this_pass and files_to_process:
                    # No new files were successfully added in this pass, but there are still files to process.
                    # This indicates a deadlock, unresolvable dependencies, or malformed protos.
                    print("Stuck in dependency resolution loop. No new files added in this pass.")
                    print(f"Remaining files to process: {[descriptor_pb2.FileDescriptorProto.FromString(f).name for f in files_to_process]}")
                    return False

            print(f"Max dependency resolution passes ({max_dependency_resolution_passes}) reached. Could not load all descriptors.")
            print(f"Remaining files to process: {[descriptor_pb2.FileDescriptorProto.FromString(f).name for f in files_to_process]}")
            return False # Max attempts reached
        except Exception as e:
            self.log(function_name='_try_add_file_descriptor_with_deps', args=[fd_proto_bytes, reflection_stub], exception=e)

            return False # Other error

    def get_method_descriptor(self, service_name: str, method_name: str):
        """
        Retrieves the method descriptor for a given gRPC service method
        using server reflection. This also populates the internal descriptor pool.

        Args:
            service_name: The fully qualified service name (e.g., "auth.AuthService").
            method_name: The name of the method (e.g., "Register").

        Returns:
            google.protobuf.descriptor.MethodDescriptor: The method descriptor
            for the specified method.

        Raises:
            RuntimeError: If the service or method is not found, or if there are
                          issues loading required Protobuf descriptors.
        """
        channel = self.connect_to_server()
        # Use the reflection_stub initialized in connect_to_server
        reflection_stub = self.reflection_stub
        if not reflection_stub:
            raise RuntimeError("Reflection stub not initialized. Call connect_to_server first.")

        try:
            # 1. First, verify if the service exists on the server
            
            list_request = reflection_pb2.ServerReflectionRequest(list_services="*")
            list_response = next(reflection_stub.ServerReflectionInfo(iter([list_request])))

            if not list_response.HasField('list_services_response'):
                raise RuntimeError("Server reflection did not return service list.")

            service_exists = any(s.name == service_name
                                for s in list_response.list_services_response.service)

            if not service_exists:
                available_services = [s.name for s in list_response.list_services_response.service]
                raise RuntimeError(
                    f"Service '{service_name}' not found. Available services: {available_services}"
                )
            

            # 2. Load well-known types first (e.g., google/protobuf/timestamp.proto)
            # These are common and often dependencies for other protos.
            well_known_types = [
                'google/protobuf/any.proto', 
                'google/protobuf/api.proto',
                'google/protobuf/descriptor.proto',
                'google/protobuf/duration.proto,'
                'google/protobuf/empty.proto',
                'google/protobuf/field_mask.proto',
                'google/protobuf/source_context.proto',
                'google/protobuf/struct.proto',
                'google/protobuf/timestamp.proto',
                'google/protobuf/type.proto',
                'google/protobuf/wrappers.proto'
            ]

            well_known_fds_bytes = []
            for type_name in well_known_types:
                try:
                    type_request = reflection_pb2.ServerReflectionRequest(
                        file_by_filename=type_name
                    )
                    type_response = next(reflection_stub.ServerReflectionInfo(iter([type_request])))

                    if type_response.HasField('file_descriptor_response'):
                        well_known_fds_bytes.extend(type_response.file_descriptor_response.file_descriptor_proto)
                except Exception as e:
                    print(f"Warning: Could not load well-known type {type_name}: {str(e)}")

            if not self._try_add_file_descriptor_with_deps(well_known_fds_bytes, reflection_stub):
                print("Warning: Failed to load all well-known types. This might cause issues.")

            # 3. Now, load the service descriptor and its dependencies
            
            service_request = reflection_pb2.ServerReflectionRequest(
                file_containing_symbol=service_name
            )
            service_response = next(reflection_stub.ServerReflectionInfo(iter([service_request])))

            if not service_response.HasField('file_descriptor_response'):
                raise RuntimeError(f"No descriptor returned for service '{service_name}' from server reflection.")

            # Attempt to add all file descriptors received for the service and its dependencies
            
            if not self._try_add_file_descriptor_with_deps(service_response.file_descriptor_response.file_descriptor_proto, reflection_stub):
                raise RuntimeError(
                    f"Failed to load required descriptors for service '{service_name}'. "
                    "This typically indicates:\n"
                    "1. Missing proto files on the server's reflection service.\n"
                    "2. Version mismatch between client and server Protobuf definitions.\n"
                    "3. Corrupted or unresolvable proto definitions.\n"
                    "Please check server logs for proto compilation errors or ensure all .proto files are served."
                )
            

            # 4. Finally, get the method descriptor from the populated pool
            try:
                service_desc = self.pool.FindServiceByName(service_name)
                method_desc = service_desc.FindMethodByName(method_name)
                

                # DEBUG: List all known message types in the pool
                
                for file_name in sorted(list(self.loaded_files)): # Sort for consistent output
                    try:
                        file_descriptor = self.pool.FindFileByName(file_name)
                        for msg_type in sorted(file_descriptor.message_types_by_name.values(), key=lambda m: m.full_name):
                            pass
                            #print(f"  - {msg_type.full_name} (from {file_name})")
                    except KeyError:
                        print(f"  - (Error: File {file_name} not found in pool, despite being in loaded_files set)")
                

                return method_desc # Return the method descriptor itself
            except KeyError as e:
                raise RuntimeError(f"Service or method not found in descriptor pool after loading: {str(e)}")

        except grpc.RpcError as e:
            # Catch gRPC specific errors
            self.log(function_name='get_method_descriptor', args=[service_name, method_name], exception=e)
            raise RuntimeError(f"gRPC communication error while getting descriptor for {service_name}/{method_name}: {e.details()}")
        except Exception as e:
            # Catch any other unexpected errors
            self.log(function_name='get_method_descriptor', args=[service_name, method_name], exception=e)
            raise RuntimeError(f"Failed to get descriptor for {service_name}/{method_name}: {str(e)}")
        finally:
            self.close_server_connection(channel)


    def _message_to_dict(self, msg):
        try:
            def recurse(message: Message) -> dict:
                result = {}

                for field in message.DESCRIPTOR.fields:
                    name = field.name
                    value = getattr(message, name)

                    
                    if field.label == FieldDescriptor.LABEL_REPEATED and field.message_type and field.message_type.GetOptions().map_entry:
                        result[name] = {
                            k: recurse(v) if isinstance(v, Message) else v
                            for k, v in value.items()
                        }
                        continue

                
                    if field.label == FieldDescriptor.LABEL_REPEATED:
                        result[name] = [
                            recurse(v) if isinstance(v, Message) else v
                            for v in value
                        ]
                        continue

                    
                    if field.cpp_type == FieldDescriptor.CPPTYPE_MESSAGE:
                        if not message.HasField(name):
                            result[name] = None
                        else:
                            if isinstance(value, (
                                StringValue, BoolValue, Int32Value, Int64Value,
                                UInt32Value, UInt64Value, FloatValue, DoubleValue
                            )):
                                result[name] = {"value": value.value}
                            elif isinstance(value, Timestamp):
                                result[name] = {
                                    "seconds": str(value.seconds),
                                    "nanos": value.nanos
                                }
                            else:
                                result[name] = recurse(value)

                    else:
                        result[name] = value  # include default even if not set

                return result

            return recurse(msg)
        except Exception as e:
            self.log(function_name='_message_to_dict', args=[msg], exception=e)

    def make_rpc_call(self, service_name: str, method_name: str, request_data: dict, meta_data = list()):
        
        # First get the method descriptor and populate descriptor pool
        method_desc = self.get_method_descriptor(service_name, method_name)
        
        channel = self.connect_to_server()
        try:
            # Get input and output message descriptors
            input_desc = method_desc.input_type
            output_desc = method_desc.output_type
            
            # Create message classes - this is the correct modern approach
            InputMessage = message_factory.GetMessageClass(input_desc)
            OutputMessage = message_factory.GetMessageClass(output_desc)

            # Create and populate request message
            request_message = InputMessage()
            if isinstance(request_data, dict):
                ParseDict(request_data, request_message)
            elif isinstance(request_data, Message):
                request_message.CopyFrom(request_data)
            else:
                raise TypeError("request_data must be a dict or a protobuf Message instance.")

            # ParseDict(request_data, request_message)

            # Make the RPC call
            rpc_method_path = f"/{service_name}/{method_name}"
            
            response_future = channel.unary_unary(
                rpc_method_path,
                request_serializer=InputMessage.SerializeToString,
                response_deserializer=OutputMessage.FromString
            ).future(request_message, 60,  meta_data)

            response_message = response_future.result()
            
            return self._message_to_dict(response_message)

        except grpc.RpcError as e:
            self.log(function_name='make_rpc_call', args=[service_name, method_name], exception=e)
            return self.exception_to_serializable(e, {"service": service_name, "method": method_name})
        except Exception as e:
            self.log(function_name='make_rpc_call', args=[service_name, method_name], exception=e)
            return self.exception_to_serializable(e)
        finally:
            self.close_server_connection(channel)

    def get_message_cls(self, service_name, method_name):
        try:
            service_desc = self.pool.FindServiceByName(service_name)
            for method in service_desc.methods:
                if method.name.lower() == method_name.lower():
                    msg_cls = GetMessageClass(self.pool.FindMessageTypeByName(method.input_type.full_name))
                    return msg_cls
        except Exception as e:
            self.log(function_name='get_message_cls', args=[service_name, method_name], exception=e)
            return self.exception_to_serializable(e)

    def validate_execute_request(self, service_name, method_name, request_data, meta_data):
        try:
            msg_desc = self.get_method_descriptor(service_name, method_name)

            if not msg_desc:
                return False

            msg_cls = self.get_message_cls(service_name, method_name)
            if (not msg_cls):
                return False
        
            validator = ProtobufStructureValidator(msg_desc.input_type)
            is_valid, error = validator.validate_structure(request_data)

            if (not is_valid):
                return error
            
            ProtobufConverterclass = ProtobufConverter()
            converted_request = ProtobufConverterclass.to_protobuf(request_data, msg_cls)
            
            response = self.make_rpc_call(service_name, method_name, converted_request, meta_data)

            return response
        except Exception as e:
            self.log(function_name='validate_execute_request', args=[service_name, method_name, request_data, meta_data], exception=e)
            return self.exception_to_serializable(e)

    def exception_to_serializable(self, error: Exception, context: Dict[str, Any] = None) -> Dict[str, Any]:

        def make_serializable(obj):
            """Recursively converts objects to JSON-friendly formats"""
            if obj is None or isinstance(obj, (str, int, float, bool)):
                return obj
            if isinstance(obj, (list, tuple, set)):
                return [make_serializable(x) for x in obj]
            if isinstance(obj, dict):
                return {str(k): make_serializable(v) for k, v in obj.items()}
            if hasattr(obj, '__dict__'):
                return make_serializable(vars(obj))
            if isinstance(obj, (bytes, bytearray)):
                return obj.decode('utf-8', errors='replace')
            return str(obj)

        # Base structure
        result = {
            "success": False,
            "error": {
                "type": error.__class__.__name__,
                "message": str(error),
                "details": {}
            }
        }

        # Add context if provided
        if context:
            result["context"] = make_serializable(context)

        # Special handling for gRPC
        if isinstance(error, grpc.RpcError):
            result["error"].update({
                "subtype": "grpc_error",
                "code": str(getattr(error, 'code', None)),
                "code_name": getattr(error.code(), 'name', None),
                "code_value": getattr(error.code(), 'value', [None])[0],
                "details": getattr(error, 'details', None),
                "debug_info": make_serializable(
                    error.debug_error_string() 
                    if callable(getattr(error, 'debug_error_string', None)) 
                    else getattr(error, 'debug_error_string', None)
                )
            })

        # Capture all public attributes
        for attr in dir(error):
            if not attr.startswith('_'):
                try:
                    val = getattr(error, attr)
                    if not callable(val):
                        result["error"]["details"][attr] = make_serializable(val)
                except Exception:
                    pass  # Skip problematic attributes

        return make_serializable(result)
