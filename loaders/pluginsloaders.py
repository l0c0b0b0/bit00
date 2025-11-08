"""Plugin manager"""
import importlib.util
import inspect
import os
import sys
from os import listdir
from os.path import join as path_join
from os.path import dirname, exists, abspath


class PluginLoader:
    def __init__(self):
        # Get the absolute path to the bit00 package directory
        self.root_dir = dirname(dirname(abspath(__file__)))

    def _plugin_attrs_from_module(self, module):
        """Return a dict of plugin attributes from a loaded module.

        The loader supports two styles:
        - module-level variables: name, description, category, supported_modules
        - class-based plugin: find first class and read attributes from an instance
        """
        # Direct module attributes (legacy support)
        attrs = {}
        
        # Look for classes in the module
        classes = []
        for name, obj in inspect.getmembers(module, inspect.isclass):
            # skip classes imported from elsewhere
            if obj.__module__ != module.__name__:
                continue
            classes.append(obj)

        if not classes:
            return None

        # Try each class until we find one that can be instantiated
        for class_obj in classes:
            try:
                # Try to create an instance (your classes have no-arg __init__)
                instance = class_obj()
                
                # Extract attributes from instance
                attrs['name'] = getattr(instance, 'name', class_obj.__name__)
                attrs['description'] = getattr(instance, 'description', '')
                attrs['tag'] = getattr(instance, 'tag', [])
                attrs['services_matches'] =getattr(instance, 'services_matches', ())
                attrs['run_once'] = getattr(instance, 'run_once', False)
                attrs['supported_modules'] = getattr(instance, 'supported_modules', [])
                attrs['class_name'] = class_obj.__name__
                attrs['class_object'] = class_obj
                attrs['instance'] = instance
                
                return attrs
                
            except Exception as e:
                # If instantiation fails, try to get attributes from class directly
                try:
                    attrs['name'] = getattr(class_obj, 'name', class_obj.__name__)
                    attrs['description'] = getattr(class_obj, 'description', '')
                    attrs['tag'] = getattr(class_obj, 'tag', [])
                    attrs['services_matches'] =getattr(class_obj, 'services_matches', ())
                    attrs['run_once'] = getattr(class_obj, 'run_once', False)
                    attrs['supported_modules'] = getattr(class_obj, 'supported_modules', [])
                    attrs['class_name'] = class_obj.__name__
                    attrs['class_object'] = class_obj
                    return attrs
                except Exception:
                    continue  # Try next class

        return None

    def get_plugin_info(self, plugin_path):
        """Get the path, description, and supported_modules from a plugin file.

        Returns a dict mapping plugin name -> info dict, or None on failure.
        """
        plugin_name = os.path.splitext(os.path.basename(plugin_path))[0]
        # Use a stable importable module name so the plugin module can be found by import machinery
        module_name = f"bit00.plugins.{plugin_name}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, plugin_path)
            plugin_spec = importlib.util.module_from_spec(spec)
            # register in sys.modules so other code (and pickle) can import by name
            sys.modules[module_name] = plugin_spec
            spec.loader.exec_module(plugin_spec)

            attrs = self._plugin_attrs_from_module(plugin_spec)
            if not attrs or not attrs.get('name'):
                print(f"Plugin at {plugin_path} missing required attributes")
                return None

            info = {
                attrs['name']: {
                    'path': plugin_path,
                    'module_name': module_name,
                    'description': attrs.get('description', ''),
                    'supported_modules': attrs.get('supported_modules', []),
                    'tag': attrs.get('tag', []),
                    'services_matches': attrs.get('services_matches',()),
                    'run_once': attrs.get('run_once', True),
                    'class_name': attrs.get('class_name'),
                    'class_object': attrs.get('class_object'),
                    'instance': attrs.get('instance')  # Store the pre-created instance
                }
            }
            return info
        except Exception as e:
            print(f"Failed loading plugin at {plugin_path}: {e}")
            return None

    def load_plugin(self, plugin_path):
        """Load a plugin module and return the module object (or None)."""
        try:
            plugin_name = os.path.splitext(os.path.basename(plugin_path))[0]
            module_name = f"bit00.plugins.{plugin_name}"
            spec = importlib.util.spec_from_file_location(module_name, plugin_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            # If the plugin defines a discoverable class, return the class object
            attrs = self._plugin_attrs_from_module(module)
            if attrs and attrs.get('class_object'):
                return attrs.get('class_object')
            # Fallback: return the module itself (module-level-style plugin)
            return module
        except Exception as e:
            print(f"Failed loading plugin at {plugin_path}: {e}")
            return None
    
    

    def list_plugins(self):
        """List plugins without initializing them. Returns dict name->info."""
        plugins = {}
        plugins_path = path_join(self.root_dir, "plugins")
        
        if not os.path.exists(plugins_path):
            print(f"Plugins directory not found at {plugins_path}")
            return plugins
            
        try:
            items = [i for i in listdir(plugins_path) if i.endswith('.py') and i != '__init__.py']
        except OSError as e:
            print(f"Error accessing plugins directory: {e}")
            return plugins
        for item in items:
            plugin_path = path_join(plugins_path, item)
            plugin_data = self.get_plugin_info(plugin_path)
            if not plugin_data:
                continue
            # plugin_data maps name->info; check supported_modules and merge
            for name, info in plugin_data.items():
                plugins[name] = info
        return plugins

   

