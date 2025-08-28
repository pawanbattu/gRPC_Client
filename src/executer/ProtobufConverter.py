from google.protobuf import wrappers_pb2
from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.message import Message
from typing import Any, Dict, List, Union
from google.protobuf.timestamp_pb2 import Timestamp
from datetime import datetime
from executer.helper import helper
import json
helpercls = helper()

class ProtobufConverter:
    """Robust Protocol Buffers converter with proper list handling."""
    
    WRAPPER_TYPES = {
        'google.protobuf.BoolValue': wrappers_pb2.BoolValue,
        'google.protobuf.Int32Value': wrappers_pb2.Int32Value,
        'google.protobuf.Int64Value': wrappers_pb2.Int64Value,
        'google.protobuf.UInt32Value': wrappers_pb2.UInt32Value,
        'google.protobuf.UInt64Value': wrappers_pb2.UInt64Value,
        'google.protobuf.StringValue': wrappers_pb2.StringValue,
    }

    CUSTOM_CONVERTERS = {
        "google.protobuf.Timestamp": lambda v: (
            Timestamp(seconds=int(datetime.fromisoformat(v).timestamp()))
            if isinstance(v, str) 
            else v
            ),
        }
    

    @classmethod
    def to_protobuf(
        cls,
        input_data: Dict[str, Any],
        message_class: Message,
        field_mapping: Dict[str, str] = None,
        *,
        track_explicit_defaults: bool = False,
    ) -> Message:
        """Convert dictionary to protobuf message with advanced features.
        
        Args:
            input_data: Input dictionary.
            message_class: Protobuf message class or instance.
            field_mapping: Optional input-to-protobuf field name mapping.
            track_explicit_defaults: If True, clears fields not in input_data.
        
        Returns:
            Populated protobuf message.
        """
        try:
            msg = message_class() if isinstance(message_class, type) else message_class
            field_mapping = field_mapping or {}
            explicitly_set = set()

            for input_name, value in input_data.items():
                pb_name = field_mapping.get(input_name, input_name)
                
                # Handle nested paths (e.g., 'nested.field.path')
                if '.' in pb_name:
                    try:
                        field = cls._get_nested_field(msg.DESCRIPTOR, pb_name)
                        pb_name = field.name  # Use final field name
                    except ValueError as e:
                        print(f"Warning: {str(exception=e)}")
                        continue
                elif not hasattr(msg, pb_name):
                    print(f"Warning: Unknown field '{input_name}' (tried as '{pb_name}')")
                    continue
                else:
                    field = msg.DESCRIPTOR.fields_by_name[pb_name]

                explicitly_set.add(pb_name)

                try:
                    # Handle oneof fields
                    if field.containing_oneof:
                        current_field = msg.WhichOneof(field.containing_oneof.name)
                        if current_field and current_field != pb_name:
                            print(f"Warning: Overwriting oneof field '{current_field}' with '{pb_name}'")

                    # Handle custom converters (e.g., Timestamp)
                    if field.message_type and field.message_type.full_name in cls.CUSTOM_CONVERTERS:
                        value = cls.CUSTOM_CONVERTERS[field.message_type.full_name](value)

                    # Handle repeated fields
                    if field.label == FieldDescriptor.LABEL_REPEATED:
                        if not isinstance(value, list):
                            value = [value]
                        repeated_field = getattr(msg, pb_name)
                        for item in value:
                            if field.message_type:
                                nested_msg = repeated_field.add()
                                cls.to_protobuf(item, nested_msg, field_mapping)
                            else:
                                repeated_field.append(cls._convert_single_value(item, field))
                        continue

                    # Handle wrapper types
                    if cls._is_wrapper_type(field):
                        wrapper = getattr(msg, pb_name)
                        wrapper.value = cls._convert_single_value(
                            value['value'] if isinstance(value, dict) else value,
                            field.message_type.fields_by_name['value']
                        )
                    # Handle nested messages
                    elif field.message_type:
                        nested_msg = getattr(msg, pb_name)
                        cls.to_protobuf(value, nested_msg, field_mapping)
                    # Handle primitives
                    else:
                        setattr(msg, pb_name, cls._convert_single_value(value, field))

                except Exception as e:
                    print(f"Warning: Failed to set field {pb_name}: {str(exception=e)}")

            # Clear fields not explicitly set (if enabled)
            if track_explicit_defaults:
                for field in msg.DESCRIPTOR.fields:
                    if field.name not in explicitly_set:
                        msg.ClearField(field.name)

            return msg
        except Exception as e:
            helpercls.log('to_protobuf', [input_data], exception=e)
            return False

    @classmethod
    def _get_nested_field(cls, msg_descriptor, field_path: str) -> FieldDescriptor:
        try:
            """Resolve nested field paths like 'nested.field.path'."""
            parts = field_path.split('.')
            current_descriptor = msg_descriptor

            for part in parts:
                field = current_descriptor.fields_by_name.get(part)
                if not field:
                    raise ValueError(f"Field '{part}' not found in path '{field_path}'")
                if field.message_type:
                    current_descriptor = field.message_type
                elif part != parts[-1]:
                    raise ValueError(f"Non-message field '{part}' in path '{field_path}'")
            
            return field
        except Exception as e:
            helpercls.log('_get_nested_field', [cls, msg_descriptor, field_path], exception=e)
            return False

    @classmethod
    def _is_wrapper_type(cls, field: FieldDescriptor) -> bool:
        try:
            """Check if a field is a wrapper type."""
            return (field.message_type and 
                    field.message_type.full_name in cls.WRAPPER_TYPES)
        except Exception as e:
            helpercls.log('_is_wrapper_type', [cls, field], exception=e)
            return False

    @classmethod
    def _convert_single_value(cls, value: Any, field: FieldDescriptor) -> Any:
        
        """Convert a single value to the correct protobuf type."""
        if value is None:
            return field.default_value

        # Handle enums
        if field.enum_type:
            if isinstance(value, str):
                enum_val = field.enum_type.values_by_name.get(value)
                if enum_val:
                    return enum_val.number
            return int(value)

        # Handle basic types
        try:
            if field.type == FieldDescriptor.TYPE_BOOL:
                return bool(value) if str(value).lower() != 'false' else False
            elif field.type in (FieldDescriptor.TYPE_INT32, FieldDescriptor.TYPE_INT64,
                             FieldDescriptor.TYPE_UINT32, FieldDescriptor.TYPE_UINT64):
                return int(value)
            elif field.type in (FieldDescriptor.TYPE_FLOAT, FieldDescriptor.TYPE_DOUBLE):
                return float(value)
            elif field.type == FieldDescriptor.TYPE_STRING:
                return str(value)
            elif field.type == FieldDescriptor.TYPE_BYTES:
                return value.encode() if isinstance(value, str) else bytes(value)
        except (ValueError, TypeError) as e:
            helpercls.log('_convert_single_value', [cls, value, field], exception=e)
            raise ValueError(
                f"Cannot convert value '{value}' to {cls._get_type_name(field.type)} "
                f"for field '{field.name}'"
            ) from e

        return value

    @classmethod
    def _get_type_name(cls, field_type: int) -> str:
        try:
            """Get human-readable type name."""
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
                FieldDescriptor.TYPE_BYTES: "bytes",
                FieldDescriptor.TYPE_UINT32: "uint32",
                FieldDescriptor.TYPE_ENUM: "enum",
                FieldDescriptor.TYPE_SFIXED32: "sfixed32",
                FieldDescriptor.TYPE_SFIXED64: "sfixed64",
                FieldDescriptor.TYPE_SINT32: "sint32",
                FieldDescriptor.TYPE_SINT64: "sint64",
            }
            return type_names.get(field_type, "unknown")
        except Exception as e:
            helpercls.log('_get_type_name', [cls, field_type], exception=e)
    

    @classmethod
    def to_dict(cls, msg: Message, field_mapping: Dict[str, str] = None) -> Dict[str, Any]:
        try:
            """Convert protobuf message back to dictionary."""
            result = {}
            field_mapping = field_mapping or {}
            reverse_mapping = {v: k for k, v in field_mapping.items()}
            
            for field_name, field in msg.DESCRIPTOR.fields_by_name.items():
                value = getattr(msg, field_name)
                output_name = reverse_mapping.get(field_name, field_name)
                
                if cls._is_wrapper_type(field):
                    result[output_name] = {'value': value.value}
                else:
                    result[output_name] = value
                    
            return result
        except Exception as e:
            helpercls.log('to_dict', [cls, msg, field_mapping], exception=e)

    @classmethod
    def to_json(cls, msg: Message, field_mapping: Dict[str, str] = None) -> str:
        """Convert protobuf message to JSON string."""
        return json.dumps(cls.to_dict(msg, field_mapping), indent=2)