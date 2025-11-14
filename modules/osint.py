"""OSINT module for gathering intelligence on domains and IPs."""
from threading import Lock
import os
import asyncio
import time
from typing import Optional
from concurrent.futures import FIRST_COMPLETED
from dataclasses import dataclass, field
from typing import Optional, Dict, List

from loaders.pluginsloaders import PluginLoader
from helpers.io import info, error, warn, debug
from helpers.utils import is_domain, extract_base_domain, calculate_elapsed_time

p_loader = PluginLoader()

@dataclass
class osint:
    """OSINT reconnaissance module.
    
    Handles:
    - DNS enumeration
    - WHOIS lookups
    - Subdomain discovery
    - Service detection
    Represents the state of a target being processed."""

    target: Optional[str] = None
    target_type: Optional[str] = None
    basedomain: Optional[str] = None
    basedir = Optional[str]
    only_recon = Optional[bool]

    # These will be initialized in __post_init__
    results: Dict = field(init=False)
    pending: List = field(init=False)
    scans: List = field(init=False)
    plugins: Dict = field(init=False)

    def __post_init__(self):
        """Initialize mutable attributes after __init__."""
        self.results = {}
        self.pending = []
        self.scans = []
        self.plugins = {}

    
    def set_target_type(self, target):
        self.target = target
        if not is_domain(target):
            self.target_type = "ipaddress"
        else:
            self.basedomain = extract_base_domain(target)
            self.target_type = "domain"

    def loader_plugins(self):
        p_loader.list_plugins()
        return {m: props for m, props in p_loader.list_plugins().items() if "osint" in props["supported_modules"]}

    def get_plugin(self, plugin_name):
        plugins = self.loader_plugins()
        return {m: props for m, props in plugins.items() if plugin_name in props["name"]}

    def setup_plugins(self, target):
        if not is_domain(target):
            return {m: props for m, props in self.loader_plugins().items() if "revlookup" in props["tag"]}
        return {m: props for m, props in self.loader_plugins().items() if "discover" in props["tag"]}
    
    def setup_onlyrecon_plugins(self, target):
        if not is_domain(target):
            return {m: props for m, props in self.loader_plugins().items() if "revlookup" in props["tag"]}
        return {
            m: props for m, props in self.loader_plugins().items() 
            if "discover" in props["tag"] or m in ['SpiderfootEmail', 'DNSReconRegisters', 'CurlGeolocation','ScrapingGitHub','TheHarvesterEmail']
        }

    def setup_scan_plugins(self):
        return {m: props for m, props in self.loader_plugins().items() if "subdomain" in props["tag"] or "ipnet" in props["tag"]}

    def check_run_once(self, plug, props):
        if props['run_once'] == True:
            if (plug,) in self.scans:
                return False
            else:
                self.scans.append(tuple([plug]))
                return True
        else:
            return True

    async def scan_osint(self, ipaddress=None, subdomain=None, flag=None):

        scan_plugins = self.setup_scan_plugins()

        targets_to_scan = []

        if flag == "ip-subdomain":
            debug("Starting OSINT Scan on both targets: {byellow}{ipaddress}{rst} and {byellow}{subdomain}{rst}", 
                ipaddress=ipaddress, subdomain=subdomain)
            targets_to_scan = [("ipnet", ipaddress), ("subdomain", subdomain)]
    
        elif flag == "subdomain":
            debug("Starting OSINT Scan on: {byellow}{subdomain}{rst}", subdomain=subdomain)
            targets_to_scan = [("subdomain", subdomain)]
    
        else:
            warn("Unknown flag: {flag}", flag=flag)
            return
        
        for target_type, target_value in targets_to_scan:
            for plug, props in scan_plugins.items():
                module = props['supported_modules'][0]
                if target_type in props["tag"]:
                    props["tag"].append(target_value)
                    #print(props["tag"])
                    if not self.check_run_once(plug=plug, props=props):
                        continue
                    
                    plugin = p_loader.load_plugin(props["path"])
                    try:
                        debug("Plugin instance initialized:  {bgreen}{plugin}{rst}", plugin=plug)
                        self.pending.add(asyncio.create_task(plugin.run(
                                target=target_value,
                                output = self.basedir,
                                tag = props["tag"],
                                module = module)
                                )
                            )
                    except Exception as e:
                        error("Plugin {plugin} failed on {target_type}: {_e}", 
                        plugin=plug, target_type=target_type, _e=str(e))             
    
    async def recon_osint(self):        
        """Main OSINT reconnaissance"""
        
        debug("Starting OSINT Enumeration on target: {byellow}{target}{rst}", target=self.target)

        for plug, props in self.plugins.items():
            module = props['supported_modules'][0]
            props["tag"].append(self.target)
            plugin = p_loader.load_plugin(props["path"])

            try:
                debug("Plugin instance initialized:  {bgreen}{plugin}{rst}", plugin=plug)
                
                self.pending.append(asyncio.create_task(plugin.run(
                        target= self.target,
                        output = self.basedir, 
                        tag = props["tag"], 
                        module = module
                        )
                    )
                )

            except Exception as e:
                error("Plugin {plugin} failed: {_e}", 
                    plugin=plug, _e=str(e))  

    async def update_results(self, ips=None, subdomain=None):
        #print(results)
        if ips not in self.results.keys():
            info('Found {bmagenta}{domain}{rst} at {bmagenta}{ipaddress}{rst} on target {byellow}{address}{rst}', 
                    domain=subdomain, ipaddress=ips, address=self.target)
            self.results[ips] = [subdomain]
            flag = 'ip-subdomain'
            return ips, subdomain, flag
        elif subdomain not in self.results[ips]:
            info('Found {bmagenta}{domain}{rst} at {bmagenta}{ipaddress}{rst} on target {byellow}{address}{rst}', 
                domain=subdomain, ipaddress=ips, address=self.target)
            self.results[ips].append(subdomain)
            flag = 'subdomain'
            return ips, subdomain, flag
        else:
            return None, None, None
            

    async def execute_async(self):
        """Async execution for OSINT"""
        await self.recon_osint()

        while self.pending:
            
            done, self.pending = await asyncio.wait(self.pending, return_when=FIRST_COMPLETED) 
            
            for task in done:
                try:
                    result = task.result()
                    if not isinstance(result, dict):
                        debug('Skipping non-dict task result: {result}', result=result)
                        continue

                    if result.get('returncode') == 0 and result.get('name') == 'discover':

                        for ips, subdomains in result['matches'].items():
                            if '\n'.join(subdomains).endswith(self.basedomain):
                                for _subdomain in subdomains:
                                    update_result = await self.update_results(ips, _subdomain)

                                    try:
                                        ipaddress, subdomain, flag = update_result
                                    
                                        if self.only_recon == True:
                                            #info('Running only osint recon for {byellow}{target}{rst}', target=self.target)
                                            continue

                                        if not ipaddress and not subdomain and not flag:
                                            continue
                            
                                        await self.scan_osint(ipaddress=ipaddress, subdomain=subdomain, flag=flag)

                                    except (TypeError, ValueError) as e:
                                        error('Error unpacking update_results: {_e}. Result: {result}', 
                                                _e=str(e), result=update_result)
                                        continue
                            
                except AttributeError as e:
                    error('Attribute error in task result: {_e}', _e=str(e))
                except Exception as e:
                    error('Error processing task result: {_e}', _e=str(e))
        
        return {"status": "completed", "results": True}
    
    async def execute(self, target, args):
        
        """Main execution method"""
        start_time = time.time()
        try:
            self.set_target_type(target)
            if not args.only_osintrecon:
                self.plugins = self.setup_plugins(target)
            else:
                self.only_recon = True    
                self.plugins = self.setup_onlyrecon_plugins(target)

            if args.plugin:
                self.plugins = self.get_plugin(args.plugin)    
            
            #self.plugins = self.setup_plugins(target)
            
            if not self.basedomain:
                self.basedir = os.path.abspath(os.path.join(args.outputdir, self.target))
            else:
                self.basedir = os.path.abspath(os.path.join(args.outputdir, self.basedomain))
            
            os.makedirs(self.basedir, exist_ok=True)
            
            scan_dir = str(os.path.abspath(os.path.join(self.basedir, 'scans')))
            os.makedirs(scan_dir, exist_ok=True)
            
            if not args.only_scans_dir:
                subdirs = ['scans/recon', 'scans/info', 'scans/tech']
                for subdir in subdirs:
                    full_path = os.path.abspath(os.path.join(self.basedir, subdir))
                    os.makedirs(full_path, exist_ok=True)

            # Execute the async operations
            await self.execute_async()
            return info("OSINT reconnaissance against {byellow}{target}{rst} finished successfully in {time}", 
                        target=target, time=calculate_elapsed_time(start_time))
            
        except Exception as e:
            error("OSINT error for {target}: {_e}", target=target, _e=str(e))
            return error("OSINT Error: {target}")

            
