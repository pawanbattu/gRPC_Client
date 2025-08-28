import grpc
from typing import Dict, Any
import logging
import traceback
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient
import base64
import os
from pathlib import Path
import shutil

class helper:

    def __init__(self, log_to_console=False):
        log_file="error.log"
        self.logger = logging.getLogger("FunctionLogger")
        self.logger.setLevel(logging.DEBUG)

        # Prevent adding duplicate handlers
        if not self.logger.handlers:
            # File handler
            file_handler = logging.FileHandler(log_file)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

            # Console handler
            if log_to_console:
                console_handler = logging.StreamHandler()
                console_handler.setFormatter(formatter)
                self.logger.addHandler(console_handler)

    def log(self, function_name: str, args=None, kwargs=None, output=None, exception: Exception = None):
        args = args or []
        kwargs = kwargs or {}

        
        self.logger.info(f"Function: {function_name}")

        if (args):
            self.logger.debug(f"Input args: {args}")
        if (kwargs):
            self.logger.debug(f"Input kwargs: {kwargs}")

        if output is not None:
            self.logger.debug(f"Output: {output}")

        if exception is not None:
            self.logger.error(f"Exception in function '{function_name}': {str(exception)}")
            self.logger.error(traceback.format_exc())
        self.logger.info(f"----------------------------------------------------------------------------------------------------:end")

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
    



    def get_oauth2_token(self, client_id, client_secret, token_url, scope=None):
        try:
            client = BackendApplicationClient(client_id=client_id)
            oauth = OAuth2Session(client=client, scope=scope)
            token = oauth.fetch_token(token_url=token_url,
                                    client_id=client_id,
                                    client_secret=client_secret)
            return token
        except Exception as e:
            return self.exception_to_serializable(e)
        
    def convert_auth(self, data):
        try:
            response = {'error' : True, 'data': None, 'auth_type' : None}
            if not isinstance(data, dict):
                response['error'] = False
                return response
            
            if ('auth_type' not in data and not data['auth_type']):
                response['error'] = False
                return response
            
            response['auth_type'] = data['auth_type']
            
            if data['auth_type'] == 'api_key':
                response['data'] = (data['key_name'], data['key_value'])
            elif data['auth_type'] == 'bearer_token':
                response['data'] = ('authorization', f'Bearer {data["token"]}')
            elif data['auth_type'] == 'basic_auth':
                username = data['username'] if 'username' in data else None
                password = data['password'] if 'password' in data else None
                user_pass_string = f"{username}:{password}"
                auth_str = base64.b64encode(user_pass_string.encode('utf-8')).decode('utf-8')
                response['data'] = ('authorization', f'Basic {auth_str}')
            elif data['auth_type'] == 'oauth2':
                if not all(key in data for key in ["client_id", "client_secret", "token_url"]):
                    return response
                if ('scope' in data and not isinstance(data['scope'], list)):
                    data['scope'] = list(data['scope'])
                
                token = self.get_oauth2_token(data['client_id'], data['client_secret'], data['token_url'], data['scope'])
                if token and "access_token" in token:
                    access_token = token["access_token"]
                    response['data'] = ("authorization", f"Bearer {access_token}")

            response['error'] = False

            return response
        except Exception as e:
            self.log(function_name='convert_auth', args=[data], exception=e)
            return self.exception_to_serializable(e)
        

    def cleanup(self):
        folder = os.path.join(Path.cwd().parent, 'compiled_proto')
        for filename in os.listdir(folder):
            file_path = os.path.join(folder, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)  
                elif os.path.isdir(file_path):
                    import shutil
                    shutil.rmtree(file_path)
            except Exception as e:
                self.log(function_name='cleanup', args=[folder], exception=e)
