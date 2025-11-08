import os
import time
import asyncio
from sys import exit
from os.path import exists
from concurrent.futures import ProcessPoolExecutor, as_completed

 # Local libraries and modules
from bit00 import gen_cli_args
from helpers.io import error, info, fail
from helpers.utils import parse_targets, calculate_elapsed_time
from loaders.pluginsloaders import PluginLoader
from loaders.modulesloaders import ModulesLoader
from loaders.reportsloaders import ReportsLoader

m_loader = ModulesLoader()
p_loader = PluginLoader()

def run_target(module_path, target, args):
    """Top-level helper for ProcessPoolExecutor: load module class from path, instantiate it and run its async execute.

    Accepts module_path (string) to avoid pickling class objects. Each worker will load the module file directly.
    """
    try:
        loader = ModulesLoader()
        module_class = loader.load_module(module_path)
        instance = module_class()
        return asyncio.run(instance.execute(target, args))
    except Exception as e:
        return f"Error: {str(e)}"


async def start_run(module, args, targets):  # noqa: RUF029
    futures = []
    start_time = time.time()
    with ProcessPoolExecutor(max_workers=args.concurrent_targets) as executor:
        for target in targets:
            future = executor.submit(run_target, module, target, args)
            futures.append(future)
        
        try:
            for future in as_completed(futures):
                try:
                    result = future.result()
                    info('{bgreen}Finished all targets in {elapsed_time}!{rst}', 
                          elapsed_time=calculate_elapsed_time(start_time))
                except Exception as e:
                    error(f"Error processing target: {e}")
        except KeyboardInterrupt:
            fail("Interrupted by user")
        
    if not args.results:    
        if "osint" in args.module:
            osint_loader = ReportsLoader("osint")
            osint_loader.generate_reports()
        else:
            netscan_loader = ReportsLoader("netscan") 
            netscan_loader.generate_reports()


def main() -> None:
    """Main entry point."""
    args = gen_cli_args()
    targets= []
    
    if hasattr(args, "verbose") and args.verbose:
        os.environ['SCANNER_VERBOSE'] = str(args.verbose)
    
    if args.concurrent_targets <= 0:
        error('Argument -ct/--concurrent-targets: must be at least 1.')
        exit()
            
    if args.concurrent_scans <= 0:
        error('Argument -cs/--concurrent-scans: must be at least 1.')
        exit()
    os.environ['CONCURRENT_SCANS'] = str(args.concurrent_scans)

    if hasattr(args, "targets") and args.targets:
        for target_input in args.targets:
            try:
                if exists(target_input) and os.path.isfile(target_input):
                    # Handle file input - read targets from file
                    info(f"Reading targets from file: {target_input}")
                    with open(target_input) as target_file:
                        for line in target_file:
                            line = line.strip()
                            if line and not line.startswith('#'):  # Skip empty lines and comments
                                targets.extend(parse_targets(line))
                else:
                    # Handle direct input (IP, CIDR, domain, etc.)
                    info(f"Processing target: {target_input}")
                    targets.extend(parse_targets(target_input))
                
            except Exception as e:
                fail(f"Failed to parse target '{target_input}': {e}")
                continue
        
        if targets:
            info(f"Total targets to process: {len(targets)}")
        else:
            error("No valid targets found in the provided input")
    
    if args.module not in m_loader.get_modules().keys():
        error(f"Error: Module {args.module} not found")
    
    module_path = m_loader.get_modules()[args.module]["path"]

    plugins = p_loader.list_plugins()

    if args.list_plugins: 
        module_plugins = {m: props for m, props in plugins.items() if args.module in props["supported_modules"]}
        for plugs, descriptions in module_plugins.items():
            info("{plug} - {description}", plug=plugs, description=descriptions['description'])
    
    if args.module and args.results:
        loader = ReportsLoader(args.module)
        loader.generate_reports_from_dir(args.results)

    try:
        asyncio.run(start_run(module_path, args, targets))
    except KeyboardInterrupt:
        print(f"Got keyboard interrupt")
    finally:
        # results write report
        # db_engine.dispose()    
        print("Exiting...")

if __name__ == "__main__":
    main()
    