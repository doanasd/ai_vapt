import os
import importlib
import inspect
from plugins.base_plugin import BasePlugin

def load_all_plugins(plugin_folder="plugins"):
    loaded_plugins = []
    for filename in sorted(os.listdir(plugin_folder)):
        if filename.endswith(".py") and filename not in ["__init__.py", "base_plugin.py"]:
            module_name = f"{plugin_folder}.{filename[:-3]}"
            module = importlib.import_module(module_name)
            
            for _, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                    plugin_instance = obj()
                    loaded_plugins.append(plugin_instance)
                    print(f"[*] Đã nạp plugin: {plugin_instance.METADATA['name']}")
    return loaded_plugins

if __name__ == "__main__":
    print("Đang test Plugin Loader...")
    plugins = load_all_plugins()
    print(f"Tổng số plugin sẵn sàng: {len(plugins)}")
