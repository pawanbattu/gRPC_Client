from google.protobuf.descriptor import Descriptor, FieldDescriptor
from google.protobuf.message import Message
from typing import Dict, Optional, Tuple, Union, List, Any, Set
import json
import re
from executer.helper import helper


class ProtobufStructureValidator():
    def __init__(self, message_class: Union[Message, Descriptor]):
        """
        Initialize with either a message class or descriptor
        
        Args:
            message_class: Either a protobuf Message class or its Descriptor
        """
    
        if isinstance(message_class, Descriptor):
            self.descriptor = message_class
        else:
            self.descriptor = message_class.DESCRIPTOR
        
        # All known wrapper types in protobuf
        self.known_wrappers = {
            'google.protobuf.DoubleValue',
            'google.protobuf.FloatValue',
            'google.protobuf.Int64Value',
            'google.protobuf.UInt64Value',
            'google.protobuf.Int32Value',
            'google.protobuf.UInt32Value',
            'google.protobuf.BoolValue',
            'google.protobuf.StringValue',
            'google.protobuf.BytesValue',
            'google.protobuf.Timestamp',
            'google.protobuf.Duration',
            'google.protobuf.FieldMask',
            'google.protobuf.Struct',
            'google.protobuf.Value',
            'google.protobuf.ListValue',
            'google.protobuf.NullValue',
            'google.protobuf.Any'
        }
        
        # Map of protobuf types to Python types for validation
        self.type_validators = {
            FieldDescriptor.TYPE_DOUBLE: (float, int),
            FieldDescriptor.TYPE_FLOAT: (float, int),
            FieldDescriptor.TYPE_INT64: (int,),
            FieldDescriptor.TYPE_UINT64: (int,),
            FieldDescriptor.TYPE_INT32: (int,),
            FieldDescriptor.TYPE_FIXED64: (int,),
            FieldDescriptor.TYPE_FIXED32: (int,),
            FieldDescriptor.TYPE_BOOL: (bool,),
            FieldDescriptor.TYPE_STRING: (str,),
            FieldDescriptor.TYPE_BYTES: (str, bytes),
            FieldDescriptor.TYPE_UINT32: (int,),
            FieldDescriptor.TYPE_SFIXED32: (int,),
            FieldDescriptor.TYPE_SFIXED64: (int,),
            FieldDescriptor.TYPE_SINT32: (int,),
            FieldDescriptor.TYPE_SINT64: (int,),
        }

        self.helpercls = helper()
        

    def validate_structure(self, json_data: Union[Dict, str]) -> Tuple[bool, Optional[str]]:
        """
        Validate that the JSON structure matches the protobuf message structure.
        
        Args:
            json_data: Either a JSON string or a parsed dictionary
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            self.helpercls.log('validate_structure', [json_data])
            
            if isinstance(json_data, str):
                if not self.is_valid_json(json_data):
                    return False, "Invalid JSON string"
                json_data = json.loads(json_data)
                
            return self._validate_structure(json_data)
        except Exception as e:
            self.helpercls.log('validate_structure', [json_data], exception=e)
            return False, f"Validation error: {str(e)}"

    def _validate_structure(self, json_data: Dict) -> Tuple[bool, Optional[str]]:
        """Internal validation implementation"""
        try:
            
            
            if not isinstance(json_data, dict):
                return False, "Input must be a JSON object"
            
            # Check for unknown fields
            valid_fields = {field.name for field in self.descriptor.fields}
            for field_name in json_data.keys():
                if field_name not in valid_fields:
                    return False, f"Unknown field '{field_name}'"

            # Validate each field
            for field in self.descriptor.fields:
                if field.name in json_data:
                    is_valid, error = self._validate_field(field, json_data[field.name])
                    if not is_valid:
                        return False, error
                elif field.label == FieldDescriptor.LABEL_REQUIRED:
                    return False, f"Missing required field '{field.name}'"
            
            return True, None
        except Exception as e:
            self.helpercls.log('_validate_structure', [json_data], exception=e)
            return False, f"Validation error: {str(e)}"

    def _validate_field(self, field: FieldDescriptor, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate a single field's structure and type"""
        try:
            
            
            if field.label == FieldDescriptor.LABEL_REPEATED:
                if not isinstance(value, list):
                    return False, f"Field '{field.name}' should be an array"
                for item in value:
                    is_valid, error = self._validate_field_value(field, item)
                    if not is_valid:
                        return False, error
                return True, None
            
            return self._validate_field_value(field, value)
        except Exception as e:
            self.helpercls.log('_validate_field', [field, value], exception=e)
            return False, f"Validation error for field '{field.name}': {str(e)}"

    def _validate_field_value(self, field: FieldDescriptor, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate a single field value's structure and type"""
        try:
            
            
            # Handle wrapper types
            if self._is_wrapper_type(field):
                if not isinstance(value, dict) or 'value' not in value:
                    return False, f"Field '{field.name}' must be an object with 'value' property"
                wrapped_value = value['value']
                return self._validate_primitive(field.message_type.fields_by_name['value'], wrapped_value)
            
            # Handle special well-known types
            if field.type == FieldDescriptor.TYPE_MESSAGE:
                if field.message_type.full_name == 'google.protobuf.Timestamp':
                    return self._validate_timestamp(value)
                elif field.message_type.full_name == 'google.protobuf.Duration':
                    return self._validate_duration(value)
                elif field.message_type.full_name == 'google.protobuf.FieldMask':
                    return self._validate_field_mask(value)
                elif field.message_type.full_name == 'google.protobuf.Struct':
                    return self._validate_struct(value)
                elif field.message_type.full_name == 'google.protobuf.Value':
                    return self._validate_value(value)
                elif field.message_type.full_name == 'google.protobuf.ListValue':
                    return self._validate_list_value(value)
                elif field.message_type.full_name == 'google.protobuf.Any':
                    return self._validate_any(value)
                elif field.message_type.full_name == 'google.protobuf.NullValue':
                    return value is None, f"Field '{field.name}' must be null"
            
            # Handle message types
            if field.type == FieldDescriptor.TYPE_MESSAGE:
                if not isinstance(value, dict):
                    return False, f"Field '{field.name}' should be an object"
                if field.message_type is None:
                    return False, f"Field '{field.name}' has invalid message type"
                return self._validate_message(field.message_type, value)
            
            # Handle enum types
            if field.type == FieldDescriptor.TYPE_ENUM:
                return self._validate_enum(field, value)
            
            # Handle primitive types
            return self._validate_primitive(field, value)
        except Exception as e:
            self.helpercls.log('_validate_field_value', [field, value], exception=e)
            return False, f"Validation error for field value '{field.name}': {str(e)}"

    def _validate_primitive(self, field: FieldDescriptor, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate primitive field types"""
        try:
            
            expected_types = self.type_validators.get(field.type, None)
            if expected_types is None:
                return True, None  # Non-primitive type, skip validation
            
            if not isinstance(value, expected_types):
                type_names = [t.__name__ for t in expected_types]
                return False, f"Field '{field.name}' should be of type {', '.join(type_names)}"
            
            # Additional validation for specific types
            if field.type == FieldDescriptor.TYPE_STRING:
                if not isinstance(value, str):
                    return False, f"Field '{field.name}' must be a string"
                    
            elif field.type == FieldDescriptor.TYPE_BYTES:
                if isinstance(value, str):
                    # Check if it's a valid base64 string
                    try:
                        import base64
                        base64.b64decode(value, validate=True)
                    except:
                        return False, f"Field '{field.name}' must be valid base64 if string"
                elif not isinstance(value, bytes):
                    return False, f"Field '{field.name}' must be bytes or base64 string"
                    
            return True, None
        except Exception as e:
            self.helpercls.log('_validate_primitive', [field, value], exception=e)
            return False, f"Validation error for primitive field '{field.name}': {str(e)}"

    def _validate_enum(self, field: FieldDescriptor, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate enum field values"""
        try:
            
            if field.enum_type is None:
                return False, f"Field '{field.name}' has invalid enum type"
            
            enum_values = [v.number for v in field.enum_type.values]
            if isinstance(value, str):
                # Check if string matches enum name
                enum_names = [v.name for v in field.enum_type.values]
                if value not in enum_names:
                    return False, f"Field '{field.name}' has invalid enum value '{value}'. Valid values: {', '.join(enum_names)}"
            elif isinstance(value, int):
                if value not in enum_values:
                    return False, f"Field '{field.name}' has invalid enum value {value}. Valid values: {enum_values}"
            else:
                return False, f"Field '{field.name}' must be an enum string or integer value"
                
            return True, None
        except Exception as e:
            self.helpercls.log('_validate_enum', [field, value], exception=e)
            return False, f"Validation error for enum field '{field.name}': {str(e)}"

    def _validate_timestamp(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate google.protobuf.Timestamp"""
        try:
            
            if not isinstance(value, str):
                return False, "Timestamp must be a string in RFC 3339 format"
            
            # Basic RFC 3339 regex check
            if not re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$', value):
                return False, "Invalid timestamp format. Expected RFC 3339 format"
                
            return True, None
        except Exception as e:
            self.helpercls.log('_validate_timestamp', [value], exception=e)
            return False, f"Validation error for timestamp: {str(e)}"

    def _validate_duration(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate google.protobuf.Duration"""
        try:
            
            if not isinstance(value, str):
                return False, "Duration must be a string"
            
            # Basic duration regex check
            if not re.match(r'^-?\d+(?:\.\d+)?s$', value):
                return False, "Invalid duration format. Expected format like '5s', '1.5s', etc."
                
            return True, None
        except Exception as e:
            self.helpercls.log('_validate_duration', [value], exception=e)
            return False, f"Validation error for duration: {str(e)}"

    def _validate_field_mask(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate google.protobuf.FieldMask"""
        try:
            
            if not isinstance(value, (str, list)):
                return False, "FieldMask must be a string or list"
                
            if isinstance(value, str):
                paths = value.split(',')
            else:
                paths = value
                
            for path in paths:
                if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*$', path.strip()):
                    return False, f"Invalid field path '{path}' in FieldMask"
                    
            return True, None
        except Exception as e:
            self.helpercls.log('_validate_field_mask', [value], exception=e)
            return False, f"Validation error for field mask: {str(e)}"

    def _validate_struct(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate google.protobuf.Struct"""
        try:
            
            if not isinstance(value, dict):
                return False, "Struct must be a JSON object"
                
            # Struct values can be any JSON-compatible value
            try:
                json.dumps(value)
            except TypeError:
                return False, "Struct contains invalid JSON value"
                
            return True, None
        except Exception as e:
            self.helpercls.log('_validate_struct', [value], exception=e)
            return False, f"Validation error for struct: {str(e)}"

    def _validate_value(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate google.protobuf.Value"""
        try:
            
            # Value can be null, number, string, bool, dict (struct), or list (ListValue)
            if value is None:
                return True, None
                
            if isinstance(value, (str, int, float, bool)):
                return True, None
                
            if isinstance(value, dict):
                return self._validate_struct(value)
                
            if isinstance(value, list):
                return self._validate_list_value(value)
                
            return False, "Value must be null, number, string, bool, dict, or list"
        except Exception as e:
            self.helpercls.log('_validate_value', [value], exception=e)
            return False, f"Validation error for value: {str(e)}"

    def _validate_list_value(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate google.protobuf.ListValue"""
        try:
            
            if not isinstance(value, list):
                return False, "ListValue must be an array"
                
            for item in value:
                is_valid, error = self._validate_value(item)
                if not is_valid:
                    return False, f"Invalid ListValue item: {error}"
                    
            return True, None
        except Exception as e:
            self.helpercls.log('_validate_list_value', [value], exception=e)
            return False, f"Validation error for list value: {str(e)}"

    def _validate_any(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Validate google.protobuf.Any"""
        try:
            
            if not isinstance(value, dict):
                return False, "Any must be an object with '@type' and 'value' fields"
                
            if '@type' not in value:
                return False, "Any must contain '@type' field"
                
            if not isinstance(value['@type'], str):
                return False, "Any '@type' must be a string"
                
            if 'value' not in value:
                return False, "Any must contain 'value' field"
                
            # Can't validate the actual value without knowing the type
            return True, None
        except Exception as e:
            self.helpercls.log('_validate_any', [value], exception=e)
            return False, f"Validation error for any: {str(e)}"

    def _is_wrapper_type(self, field: FieldDescriptor) -> bool:
        """Check if field is a known wrapper type"""
        try:
            
            return (field.type == FieldDescriptor.TYPE_MESSAGE and 
                    field.message_type is not None and 
                    field.message_type.full_name in self.known_wrappers)
        except Exception as e:
            self.helpercls.log('_is_wrapper_type', [field], exception=e)
            return False

    def _validate_message(self, descriptor: Descriptor, data: Dict) -> Tuple[bool, Optional[str]]:
        """Validate nested message structure"""
        try:
            
            if not isinstance(data, dict):
                return False, "Nested message must be an object"
            
            valid_fields = {field.name for field in descriptor.fields}
            for field_name in data.keys():
                if field_name not in valid_fields:
                    return False, f"Unknown nested field '{field_name}'"
            
            for field in descriptor.fields:
                if field.name in data:
                    is_valid, error = self._validate_field(field, data[field.name])
                    if not is_valid:
                        return False, error
                elif field.label == FieldDescriptor.LABEL_REQUIRED:
                    return False, f"Missing required nested field '{field.name}'"
            
            return True, None
        except Exception as e:
            self.helpercls.log('_validate_message', [descriptor, data], exception=e)
            return False, f"Validation error for nested message: {str(e)}"

    def get_expected_structure(self) -> Dict:
        """Generate expected structure documentation with examples"""
        try:
            
            structure = {}
            for field in self.descriptor.fields:
                try:
                    structure[field.name] = {
                        "type": self._get_field_type_description(field),
                        "required": field.label == FieldDescriptor.LABEL_REQUIRED,
                        "structure": self._get_field_structure(field),
                        "description": self._get_field_description(field)
                    }
                except Exception as e:
                    self.helpercls.log('get_expected_structure', [field], exception=e)
                    structure[field.name] = f"Error: {str(e)}"
            return structure
        except Exception as e:
            self.helpercls.log('get_expected_structure', [], exception=e)
            return {"error": f"Failed to generate structure: {str(e)}"}

    def _get_field_structure(self, field: FieldDescriptor) -> Union[Dict, List, str]:
        """Get structure documentation for a single field"""
        try:
            
            if field.label == FieldDescriptor.LABEL_REPEATED:
                return [self._get_value_structure(field)]
            return self._get_value_structure(field)
        except Exception as e:
            self.helpercls.log('_get_field_structure', [field], exception=e)
            return f"Error: {str(e)}"

    def _get_value_structure(self, field: FieldDescriptor) -> Any:
        """Get structure documentation for field value"""
        try:
            
            if self._is_wrapper_type(field):
                return {"value": self._get_type_name(field)}
            
            if field.type == FieldDescriptor.TYPE_MESSAGE:
                if field.message_type.full_name == 'google.protobuf.Timestamp':
                    return "RFC 3339 timestamp string (e.g., '2023-01-01T00:00:00Z')"
                elif field.message_type.full_name == 'google.protobuf.Duration':
                    return "Duration string (e.g., '5s', '1.5s')"
                elif field.message_type.full_name == 'google.protobuf.FieldMask':
                    return "Field mask string or array (e.g., 'field1,field2' or ['field1', 'field2'])"
                elif field.message_type.full_name == 'google.protobuf.Struct':
                    return "JSON object"
                elif field.message_type.full_name == 'google.protobuf.Value':
                    return "Any JSON value (null, number, string, bool, object, array)"
                elif field.message_type.full_name == 'google.protobuf.ListValue':
                    return "JSON array"
                elif field.message_type.full_name == 'google.protobuf.Any':
                    return {"@type": "type URL", "value": "any value"}
                elif field.message_type.full_name == 'google.protobuf.NullValue':
                    return "null"
                
                if field.message_type is None:
                    raise ValueError(f"Field '{field.name}' has no message type")
                nested_structure = {}
                for nested_field in field.message_type.fields:
                    nested_structure[nested_field.name] = self._get_field_structure(nested_field)
                return nested_structure
            
            if field.type == FieldDescriptor.TYPE_ENUM:
                return f"Enum: {[v.name for v in field.enum_type.values]}"
            
            return self._get_type_name(field)
        except Exception as e:
            self.helpercls.log('_get_value_structure', [field], exception=e)
            return f"Error: {str(e)}"

    def _get_field_type_description(self, field: FieldDescriptor) -> str:
        """Get detailed type description for a field"""
        try:
            
            if field.type == FieldDescriptor.TYPE_MESSAGE:
                if field.message_type is None:
                    return "unknown_message"
                return field.message_type.full_name
            elif field.type == FieldDescriptor.TYPE_ENUM:
                return f"enum({field.enum_type.full_name})"
            else:
                return self._get_type_name(field)
        except Exception as e:
            self.helpercls.log('_get_field_type_description', [field], exception=e)
            return f"Error: {str(e)}"

    def _get_field_description(self, field: FieldDescriptor) -> str:
        """Get additional description for a field if available"""
        try:
            
            # This could be extended to extract comments from the proto file
            return ""
        except Exception as e:
            self.helpercls.log('_get_field_description', [field], exception=e)
            return f"Error: {str(e)}"

    def _get_type_name(self, field: FieldDescriptor) -> str:
        """Get simplified type name"""
        try:
            
            type_names = {
                FieldDescriptor.TYPE_DOUBLE: "double",
                FieldDescriptor.TYPE_FLOAT: "float",
                FieldDescriptor.TYPE_INT64: "int64",
                FieldDescriptor.TYPE_UINT64: "uint64",
                FieldDescriptor.TYPE_INT32: "int32",
                FieldDescriptor.TYPE_FIXED64: "fixed64",
                FieldDescriptor.TYPE_FIXED32: "fixed32",
                FieldDescriptor.TYPE_BOOL: "bool",
                FieldDescriptor.TYPE_STRING: "string",
                FieldDescriptor.TYPE_GROUP: "group",
                FieldDescriptor.TYPE_MESSAGE: self._get_message_type_name(field),
                FieldDescriptor.TYPE_BYTES: "bytes",
                FieldDescriptor.TYPE_UINT32: "uint32",
                FieldDescriptor.TYPE_ENUM: "enum",
                FieldDescriptor.TYPE_SFIXED32: "sfixed32",
                FieldDescriptor.TYPE_SFIXED64: "sfixed64",
                FieldDescriptor.TYPE_SINT32: "sint32",
                FieldDescriptor.TYPE_SINT64: "sint64"
            }
            return type_names.get(field.type, "unknown")
        except Exception as e:
            self.helpercls.log('_get_type_name', [field], exception=e)
            return f"Error: {str(e)}"

    def _get_message_type_name(self, field: FieldDescriptor) -> str:
        """Safely get message type name"""
        try:
            
            if field.message_type is None:
                return "unknown_message"
            return field.message_type.full_name
        except Exception as e:
            self.helpercls.log('_get_message_type_name', [field], exception=e)
            return f"Error: {str(e)}"
    
    def is_valid_json(self, json_string: str) -> bool:
        """Check if a string is valid JSON"""
        try:
            json.loads(json_string)
            return True
        except json.JSONDecodeError as e:
            self.helpercls.log('is_valid_json', [json_string], exception=e)
            return False
        except Exception as e:
            self.helpercls.log('is_valid_json', [json_string], exception=e)
            return False