#!/usr/bin/env python3
"""
Bit00 - Modular Security Assessment Framework
"""
import sys
import argparse
from pathlib import Path
from loaders.modulesloaders import ModulesLoader


VERSION = "1.0"

# Add project root to path
project_root = Path(__file__).parent
sys.path.append(str(project_root))

def gen_cli_args() -> argparse.ArgumentParser:
    """Set up the main argument parser.
    
    Returns:
        Configured argument parser
    """
    # Global options
    common_parser = argparse.ArgumentParser(add_help=False) 
    common_parser.add_argument(
        "-ct", "--concurrent-targets",
        action="store",
        metavar="<number>",
        type=int,
        default=5,
        help="The maximum number of target hosts to scan concurrently. Default: %(default)s"
        )

    common_parser.add_argument(
        "-cs", "--concurrent-scans",
        action="store",
        metavar="<number>",
        type=int,
        default=10,
        help="The maximum number of scans to perform per target host. Default: %(default)s"
        )
    common_parser.add_argument(
        "-V", "--version",
        action="store_true",
        default="1.0",
        help="Display version information and exit" 
        )
    
    parser = argparse.ArgumentParser(
        description=rf"""
     ____    _   _      ___     ___  
| __ )  (_) | |_   / _ \   / _ \ 
|  _ \  | | | __| | | | | | | | |
| |_) | | | | |_  | |_| | | |_| |
|____/  |_|  \__|  \___/   \___/ 

The network reconnaissance tool with multiple modules.
Maintained as an open source project by @l0c0b0b0

Version : {VERSION}
""",    formatter_class=argparse.RawTextHelpFormatter,
            parents=[common_parser]
        )
    subparsers = parser.add_subparsers(title="Available Modules", dest="module")

    loader = ModulesLoader()
    modules = loader.get_modules()

    try:
        for module in modules:
            module_object = loader.load_module(modules[module]["argspath"])
            subparsers = module_object(subparsers,[common_parser])
    except Exception as e:
        print(f"Error loading module {module}: {str(e)}")
        sys.exit(1)

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return args

if __name__ == "__main__":
    from core.core import main
    main()