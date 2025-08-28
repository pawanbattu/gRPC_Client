import os
import re
import sys
import json
import types
import uuid
import random
import string
import grpc
from pathlib import Path
import importlib.util
from grpc_tools import protoc
import importlib.resources
import importlib.metadata
from typing import Dict, Any
import traceback
from executer import ProtobufStructureValidator
from google.protobuf.json_format import ParseDict
from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import Message, DecodeError
from google.protobuf import descriptor as desc
from google.protobuf import message
from google.protobuf import timestamp_pb2, struct_pb2, any_pb2, field_mask_pb2, duration_pb2, empty_pb2
from google.protobuf import wrappers_pb2
from google.protobuf.json_format import MessageToDict
from executer.ProtoImportManager import ProtoImportManager
from executer.ProtobufConverter import ProtobufConverter
from executer.helper import helper
from google.protobuf.wrappers_pb2 import *
from google.protobuf import (
    any_pb2,
    duration_pb2,
    empty_pb2,
    field_mask_pb2,
    struct_pb2,
    timestamp_pb2,
    wrappers_pb2,
    api_pb2,
    type_pb2,
    source_context_pb2
)
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.message import Message
from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.wrappers_pb2 import (
    StringValue, BoolValue, Int32Value, Int64Value,
    UInt32Value, UInt64Value, FloatValue, DoubleValue
    )
from datetime import datetime


class grpcprotoclient(helper):

    def __init__(self, proto_file, proto_path, host, creds = {}):
        super().__init__()
        self.host = host
        self.creds = creds
        self.importer = ProtoImportManager()
        self.base_path =  Path.cwd().parent
        self.proto_file = proto_file
        self.proto_path = proto_path
        self.pb2 = None
        self.pb2_grpc = None
        self.get_compiled_data()

    def get_compiled_data(self):
        try:
            if (self.proto_path is None):
                return False
            if (self.proto_file is None):
                return False
            random_folder = 'tab_'.join(random.choices(string.ascii_letters + string.digits, k=5))
            compiledfiles_path = os.path.join(self.base_path, 'compiled_proto', random_folder)
            self.pb2, self.pb2_grpc = self.compile_proto(self.proto_file, self.proto_path, compiledfiles_path)
            return None
        except Exception as e:
            self.log(function_name='get_compiled_data', args=[], exception=e)
            return self.exception_to_serializable(e)



    def extract_imports(self, proto_file):
        try:
            imports = []
            with open(proto_file, "r") as f:
                for line in f:
                    match = re.match(r'import\s+"(.+?)";', line.strip())
                    if match:
                        imports.append(match.group(1))
            return imports
        except Exception as e:
            self.log(function_name='extract_imports', args=[proto_file], exception=e)
            return self.exception_to_serializable(e)


    def extract_package(self, proto_file):
        try:
            with open(proto_file, "r") as f:
                for line in f:
                    match = re.match(r'\s*package\s+([\w.]+)\s*;', line)
                    if match:
                        return match.group(1)
            return ""
        except Exception as e:
            self.log(function_name='extract_package', args=[proto_file], exception=e)
            return self.exception_to_serializable(e)


    def ensure_init_files(self, output_dir):
        try:
            for root, dirs, files in os.walk(output_dir):
                init_path = os.path.join(root, "__init__.py")
                if not os.path.exists(init_path):
                    open(init_path, 'a').close()
        except Exception as e:
            self.log(function_name='ensure_init_files', args=[output_dir], exception=e)
            return self.exception_to_serializable(e)


    def find_proto_root(self, proto_file):
        try:
            proto_path = Path(proto_file).resolve()
            imports = self.extract_imports(proto_path)
            candidate = proto_path.parent
            while candidate != candidate.parent:
                all_exist = all((candidate / imp).exists() for imp in imports)
                if all_exist:
                    return str(candidate)
                candidate = candidate.parent
            raise RuntimeError("Could not resolve all imports — upload full proto tree.")
        except Exception as e:
            self.log(function_name='find_proto_root', args=[proto_file], exception=e)
            return self.exception_to_serializable(e)


    def find_package_root(self, output_dir, package_prefix):
        try:
            base_dir = Path(output_dir).resolve()
            parts = package_prefix.split(".")
            for path in base_dir.rglob("__init__.py"):
                rel = path.relative_to(base_dir)
                if parts[0] in rel.parts:
                    return str(base_dir)
            return str(base_dir)
        except Exception as e:
            self.log(function_name='find_package_root', args=[output_dir, package_prefix], exception=e)
            return self.exception_to_serializable(e)


    def patch_generated_files(self, output_dir: str):
        try:
            """
            Cleans all known broken grpcio-tools generated code from *_pb2_grpc.py files:
            - grpc.__version__
            - GRPC_VERSION usage
            - raise RuntimeError(...)
            - if grpc.__version__ < ...:
            - if _version_not_supported:
            """
            for file in Path(output_dir).rglob("*_pb2_grpc.py"):
                with open(file, "r") as f:
                    lines = f.readlines()

                new_lines = []
                skip = False
                indent_stack = []

                for i, line in enumerate(lines):
                    stripped = line.strip()

                    # Start skipping blocks with broken version checks
                    if any(bad in stripped for bad in [
                        "grpc.__version__",
                        "GRPC_VERSION",
                        "raise RuntimeError(",
                        "if grpc.__version__",
                        "if _version_not_supported"
                    ]):
                        skip = True
                        if "if " in stripped:
                            indent_stack.append(len(line) - len(line.lstrip()))
                        continue

                    # End skipping when indent drops
                    if skip:
                        if stripped == "":
                            continue
                        current_indent = len(line) - len(line.lstrip())
                        if indent_stack and current_indent <= indent_stack[-1]:
                            skip = False
                            indent_stack.pop()
                            # Reprocess current line
                            new_lines.append(line)
                        continue

                    new_lines.append(line)

                if len(new_lines) != len(lines):
                    with open(file, "w") as f:
                        f.writelines(new_lines)
        except Exception as e:
            self.log(function_name='patch_generated_files', args=[output_dir], exception=e)
            return self.exception_to_serializable(e)


    def warn_if_outdated_grpcio_tools(self):
        """
        Prints a warning if grpcio-tools is too old and likely to generate broken version checks.
        """
        try:
            version = importlib.metadata.version("grpcio-tools")
            major, minor, *_ = map(int, version.split("."))
            if (major, minor) < (1, 59):
                self.log(function_name='warn_if_outdated_grpcio_tools', args=[])
                return {"error" : f"⚠️ WARNING: Your grpcio-tools=={version} may generate broken version checks 👉 Please upgrade with: pip install -U grpcio-tools"}
        except Exception as e:
            self.log(function_name='warn_if_outdated_grpcio_tools', exception=e)


    def compile_proto(self, proto_file: str, proto_root = '', output_dir: str = "./generated"):
        try:
            self.warn_if_outdated_grpcio_tools()

            proto_file = Path(proto_file).resolve()
            if (not proto_root):
                proto_root = self.find_proto_root(proto_file)
            package_prefix = self.extract_package(proto_file)
            
            google_proto_path = str(importlib.resources.files("grpc_tools").joinpath("_proto"))

            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            proto_files = list(Path(proto_root).rglob("*.proto"))
            proto_files = [str(p) for p in proto_files]

            result = protoc.main([
                "",
                f"-I{proto_root}",
                f"-I{google_proto_path}",
                f"--python_out={output_dir}",
                f"--grpc_python_out={output_dir}",
                *proto_files
            ])

            if result != 0:
                raise RuntimeError("Protobuf compilation failed")

            self.ensure_init_files(output_dir)
            self.patch_generated_files(output_dir)

            package_root = self.find_package_root(output_dir, package_prefix)
            if package_root not in sys.path:
                sys.path.insert(0, package_root)

            proto_name = proto_file.stem
            pb2 = self.importer.import_proto_module(proto_name + "_pb2", output_dir)
            pb2_grpc = self.importer.import_proto_module(proto_name + "_pb2_grpc", output_dir)

            return pb2, pb2_grpc
        except Exception as e:
            self.log(function_name='compile_proto', args=[proto_file, proto_root, output_dir], exception=e)
            return self.exception_to_serializable(e)


    def get_enum_name(self, enum_type, value):
        try:
            enum_value = enum_type.values_by_number.get(value)
            return enum_value.name if enum_value else value
        except Exception as e:
            self.log(function_name='get_enum_name', args=[enum_type, value], exception=e)
            return value

    def get_default_value(self, field):
        type_map = {
            desc.FieldDescriptor.TYPE_STRING: "",
            desc.FieldDescriptor.TYPE_INT32: 0,
            desc.FieldDescriptor.TYPE_INT64: 0,
            desc.FieldDescriptor.TYPE_BOOL: False,
            desc.FieldDescriptor.TYPE_DOUBLE: 0.0,
            desc.FieldDescriptor.TYPE_FLOAT: 0.0,
            desc.FieldDescriptor.TYPE_BYTES: b"",
            desc.FieldDescriptor.TYPE_UINT32: 0,
            desc.FieldDescriptor.TYPE_UINT64: 0,
            desc.FieldDescriptor.TYPE_SINT32: 0,
            desc.FieldDescriptor.TYPE_SINT64: 0,
            desc.FieldDescriptor.TYPE_FIXED32: 0,
            desc.FieldDescriptor.TYPE_FIXED64: 0,
            desc.FieldDescriptor.TYPE_SFIXED32: 0,
            desc.FieldDescriptor.TYPE_SFIXED64: 0,
        }
        return type_map.get(field.type, None)

    def is_well_known_type(self, message_cls):
        try:
            """Return default value for well-known protobuf types based on their message class."""
            # Wrapper types
            if issubclass(message_cls, wrappers_pb2.BoolValue):
                return {"value": False}
            elif issubclass(message_cls, wrappers_pb2.StringValue):
                return {"value": ""}
            elif issubclass(message_cls, wrappers_pb2.Int32Value):
                return {"value": 0}
            elif issubclass(message_cls, wrappers_pb2.UInt32Value):
                return {"value": 0}
            elif issubclass(message_cls, wrappers_pb2.Int64Value):
                return {"value": 0}
            elif issubclass(message_cls, wrappers_pb2.UInt64Value):
                return {"value": 0}
            elif issubclass(message_cls, wrappers_pb2.FloatValue):
                return {"value": 0.0}
            elif issubclass(message_cls, wrappers_pb2.DoubleValue):
                return {"value": 0.0}
            elif issubclass(message_cls, wrappers_pb2.BytesValue):
                return {"value": b""}

            # Well-known structured types
            elif issubclass(message_cls, timestamp_pb2.Timestamp):
                return {"seconds": 0, "nanos": 0}
            elif issubclass(message_cls, duration_pb2.Duration):
                return {"seconds": 0, "nanos": 0}
            elif issubclass(message_cls, struct_pb2.Struct):
                return {}
            elif issubclass(message_cls, struct_pb2.Value):
                return None
            elif issubclass(message_cls, struct_pb2.ListValue):
                return []
            elif issubclass(message_cls, field_mask_pb2.FieldMask):
                return {"paths": []}
            elif issubclass(message_cls, any_pb2.Any):
                return {"@type": "type.googleapis.com/your.message.Type", "value": {}}
            elif issubclass(message_cls, empty_pb2.Empty):
                return {}

            # API descriptor types
            elif issubclass(message_cls, api_pb2.Api):
                return {"name": "", "methods": [], "options": [], "version": ""}
            elif issubclass(message_cls, api_pb2.Method):
                return {
                    "name": "",
                    "request_type_url": "",
                    "request_streaming": False,
                    "response_type_url": "",
                    "response_streaming": False,
                    "options": [],
                    "syntax": 0
                }
            elif issubclass(message_cls, api_pb2.Mixin):
                return {"name": "", "root": ""}
            elif issubclass(message_cls, type_pb2.Enum):
                return {"name": "", "value": [], "options": [], "reserved_range": [], "reserved_name": []}
            elif issubclass(message_cls, type_pb2.EnumValue):
                return {"name": "", "number": 0, "options": []}
            elif issubclass(message_cls, type_pb2.Type):
                return {
                    "name": "",
                    "fields": [],
                    "oneofs": [],
                    "options": [],
                    "source_context": {},
                    "syntax": 0
                }
            elif issubclass(message_cls, type_pb2.Field):
                return {
                    "kind": 0,
                    "cardinality": 0,
                    "number": 0,
                    "name": "",
                    "type_url": "",
                    "oneof_index": 0,
                    "packed": False,
                    "options": [],
                    "json_name": "",
                    "default_value": ""
                }
            elif issubclass(message_cls, source_context_pb2.SourceContext):
                return {"file_name": ""}

            # Unknown / non-well-known
            return None
        except Exception as e:
            self.log(function_name='is_well_known_type', args=[message_cls], exception=e)

    def get_message_template(self, msg_cls):
        try:
            wk = self.is_well_known_type(msg_cls)
            if wk is not None:
                return wk

            result = {}
            descriptor = msg_cls.DESCRIPTOR

            # Pick one field per oneof group
            oneof_chosen = {o.name: o.fields[0].name for o in descriptor.oneofs if o.fields}

            for field in descriptor.fields:
                field_name = field.name
                if field.containing_oneof and oneof_chosen.get(field.containing_oneof.name) != field.name:
                    continue

                if field.label == desc.FieldDescriptor.LABEL_REPEATED:
                    if field.message_type:
                        if field.message_type.GetOptions().map_entry:
                            key_field = field.message_type.fields_by_name["key"]
                            val_field = field.message_type.fields_by_name["value"]
                            key = self.get_default_value(key_field)
                            val = self.get_message_template(val_field.message_type._concrete_class) if val_field.message_type else self.get_default_value(val_field)
                            result[field_name] = {key: val}
                        else:
                            result[field_name] = [self.get_message_template(field.message_type._concrete_class)]
                    else:
                        result[field_name] = [self.get_default_value(field)]
                elif field.message_type:
                    result[field_name] = self.get_message_template(field.message_type._concrete_class)
                elif field.enum_type:
                    result[field_name] = self.get_enum_name(field.enum_type, 0)
                else:
                    result[field_name] = self.get_default_value(field)

            return result
        except Exception as e:
            self.log(function_name='get_message_template', args=[msg_cls], exception=e)
            return {}


    # --- Find method input message type via service descriptor ---

    def get_template_from_method_name(self, method_name: str):
        try:
            for service in self.pb2.DESCRIPTOR.services_by_name.values():
                for method in service.methods:
                    if method.name.lower() == method_name.lower():
                        msg_cls = self.pb2._sym_db.GetSymbol(method.input_type.full_name)
                        return self.get_message_template(msg_cls)
            raise ValueError(f"Method '{method_name}' not found in {self.pb2.__name__}")
        except Exception as e:
            self.log(function_name='get_template_from_method_name', args=[method_name], exception=e)
            return self.exception_to_serializable(e)

    
    def get_service_details(self):
        try:
            if not self.pb2:
                self.get_compiled_data()

            data_to_return = {}
            #data_to_return = {'full_name' : "", "name" : "", "methods" : []}            
            for service in self.pb2.DESCRIPTOR.services_by_name.values():
                service_list = {'full_name': "","name": "","methods": []}
                service_list['full_name'] = service.full_name
                service_list['name'] = service.name
                for method in service.methods:
                    service_list['methods'].append(method.name)
                data_to_return[service.full_name] = service_list

            return data_to_return
        except Exception as e:
            self.log(function_name='get_service_details', args=[], exception=e)
            return self.exception_to_serializable(e)

    def connect_to_server(self):
        try:
            if (isinstance(self.creds, dict) and len(self.creds) == 0):
                channel = grpc.insecure_channel(self.host)
            else:
                client_key = self.creds.get('client_key', '')
                client_certificate = self.creds.get('client_certificate', '')
                ca_certificate = self.creds.get('ca_certificate', '')
                root_certificates = private_key = certificate_chain = ''
                with open(ca_certificate, 'rb') as f:
                    root_certificates = f.read()
                with open(client_key, 'rb') as f:
                    private_key = f.read()
                with open(client_certificate, 'rb') as f:
                    certificate_chain = f.read()

                # Create SSL channel credentials with client certificates
                credentials = grpc.ssl_channel_credentials(
                    root_certificates=root_certificates,
                    private_key=private_key,
                    certificate_chain=certificate_chain
                )

                channel = grpc.secure_channel(self.host, credentials)
                if channel is None:
                    result = {'error' : True, 'data' : "Could not connect to server"}
                    return result

            return channel
        except Exception as e:
            self.log(function_name='connect_to_server', args=[], exception=e)
            return self.exception_to_serializable(e)
    
    def get_method_input_output_names(self, service_stub):
        try:
            """Get all method names with their request and response types"""
            service_desc = service_stub.DESCRIPTOR
            methods_info = {}
            
            for method in service_desc.methods:
                methods_info[method.name] = {
                    'request_type': method.input_type.full_name,
                    'response_type': method.output_type.full_name,
                    'client_streaming': method.client_streaming,
                    'server_streaming': method.server_streaming
                }
            
            return methods_info
        except Exception as e:
            self.log(function_name='get_method_input_output_names', args=[service_stub], exception=e)
            return self.exception_to_serializable(e)




    def call_rpc(self, stub_class, method_name, request_msg, metadata=None, is_stream=False, is_client_stream=False):
        channel = None
        try:
            channel = self.connect_to_server()
            stub = stub_class(channel)
            rpc = getattr(stub, method_name)
            response_iter = rpc(request_msg, metadata=metadata or [])
            
            return self._message_to_dict(response_iter)

        except grpc.RpcError as e:
            return self.exception_to_serializable(e)
        except Exception as e:
            self.log(function_name='call_rpc', args=[stub_class, method_name, request_msg, metadata], exception=e)
            return self.exception_to_serializable(e)
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
                        
                        result[name] = value  

                return result

            return recurse(msg)
        except Exception as e:
            self.log(function_name='_message_to_dict', args=[msg], exception=e)

    def close_server_connection(self, channel):
        try:
            if channel is not None or channel is not dict:
                channel.close()
        except Exception as e:
            self.log(function_name='close_server_connection', exception=e)
            return self.exception_to_serializable(e)

    def get_message_cls(self, pb2, methodname):
        try:
            for service in pb2.DESCRIPTOR.services_by_name.values():
                for method in service.methods:
                    if method.name.lower() == methodname.lower():
                        return pb2._sym_db.GetSymbol(method.input_type.full_name)
        except Exception as e:
            self.log(function_name='get_message_cls', args=[pb2, methodname], kwargs={}, exception=e)
            return self.exception_to_serializable(e)

    def validate_execute_request(self, service_name, method_name, request_data, meta_data):
        try:
            if not isinstance(request_data, dict):
                request_data = json.loads(request_data)
            
            msg_cls =  self.get_message_cls(self.pb2, method_name)
            validator = ProtobufStructureValidator.ProtobufStructureValidator(msg_cls())
            is_valid, error = validator.validate_structure(request_data)
            
            if (not is_valid):
                return error
            #raise Exception("The number shouldn't be an odd integer")
            converted_request = ProtobufConverter.to_protobuf(request_data, msg_cls)
            service_details = self.get_service_details()
            if (not service_details):
                return False
            stub_name = service_details[service_name]['name'] + 'Stub'
            stub_class = getattr(self.pb2_grpc, stub_name)

            response = self.call_rpc(stub_class, method_name, converted_request, meta_data)

            return response
        except Exception as e:
            self.log(function_name='validate_execute_request', args=[service_name, method_name, request_data, meta_data], kwargs={}, output=response if response else None, exception=e)
            return self.exception_to_serializable(e)
