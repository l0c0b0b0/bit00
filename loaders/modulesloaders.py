from types import ModuleType
from importlib.machinery import SourceFileLoader
from importlib.util import spec_from_file_location, module_from_spec
import sys
import os
from os import listdir
from os.path import join as path_join
from os.path import dirname, exists, abspath
from pathlib import Path


class ModulesLoader:
    def __init__(self):
        """Initialize ModulesLoader."""
        # Get the root directory of the project
        self.root_dir = dirname(dirname(abspath(__file__)))
        
    def load_module(self, module_path):
        """Load a module from path."""
        # module_name (file stem) will be used as the logical module name under the package
        module_stem = os.path.splitext(os.path.basename(module_path))[0]

        # Use a unique, importable module name so multiprocessing/pickle can locate it.
        module_name = f"bit00.modules.{module_stem}"

        # Create a module spec and load the module from the file location
        spec = spec_from_file_location(module_name, module_path)
        module = module_from_spec(spec)
        # Ensure the module is discoverable by import machinery (needed for pickle)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

        return getattr(module, module_stem)

    def get_modules(self):
        """Get all available modules."""
        modules = {}
        modu_path = path_join(self.root_dir, "modules")
        for item in listdir(modu_path):
            if item[-3:] == ".py" and item[:-3] != "__init__":
                module_name = str(item[:-3])
                module_dir = path_join(modu_path, item)
                
                module_args_path = path_join(modu_path, module_name , "mod_args.py")
            
                if exists(module_args_path):
                    modules[module_name] = {
                        "path": module_dir,
                        "argspath": module_args_path
                    }
        return modules
