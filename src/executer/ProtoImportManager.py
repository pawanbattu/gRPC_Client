import importlib.util
import sys
from pathlib import Path
import traceback
from contextlib import contextmanager
from typing import Optional, Dict, Any
from executer.helper import helper

class ProtoImportManager:
    def __init__(self):
        self._original_modules = {}
        self._import_rewrites = {
            'grpc': '_original_grpc',
            'google.grpc': '_original_google_grpc'
        }
        self.helpercls = helper()

    @contextmanager
    def _import_guard(self):
        """Context manager to handle imports safely"""
        # Backup original modules
        self._original_modules = {
            mod: sys.modules.get(mod)
            for mod in self._import_rewrites
        }
        
        # Stub out conflicting modules
        for mod in self._import_rewrites:
            if mod in sys.modules:
                sys.modules.pop(mod)
        
        try:
            yield
        finally:
            # Restore original state
            for mod, original in self._original_modules.items():
                if original is not None:
                    sys.modules[mod] = original

    def import_proto_module(self, module_name: str, search_path: str) -> Optional[object]:
        """Improved dynamic import with better loader handling"""
        try:
            search_path = Path(search_path).resolve()
            
            with self._import_guard():
                for py_file in search_path.rglob(module_name + ".py"):
                    file_path = str(py_file)
                    parent_dir = str(py_file.parent)
                    
                    # Create proper module spec
                    spec = importlib.util.spec_from_file_location(
                        f"proto_{module_name}",
                        file_path,
                        submodule_search_locations=[parent_dir]
                    )
                    
                    if spec is None or spec.loader is None:
                        continue
                        
                    module = importlib.util.module_from_spec(spec)
                    
                    # Temporarily add to sys.modules for relative imports
                    sys.modules[spec.name] = module
                    
                    try:
                        spec.loader.exec_module(module)
                        return module
                    finally:
                        # Clean up temporary module
                        if spec.name in sys.modules:
                            del sys.modules[spec.name]
            
            raise FileNotFoundError(f"Module {module_name} not found in {search_path}")
            
        except Exception as e:
            self.helpercls.log('import_proto_module', [module_name, search_path], exception=e)
            return None