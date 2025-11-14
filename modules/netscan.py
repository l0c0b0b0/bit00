"""Network scanning module for enumeration and vulnerability discovery."""
import os
import re
import time
import asyncio
from concurrent.futures import FIRST_COMPLETED
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from loaders.pluginsloaders import PluginLoader
from helpers.io import info, error, warn, debug
from helpers.utils import calculate_elapsed_time

p_loader = PluginLoader()

@dataclass
class netscan:
    target: Optional[str] = None
    target_type: Optional[str] = None
    basedir = Optional[str]
    only_portscan = Optional[bool]

    # These will be initialized in __post_init__
    results: Dict = field(init=False)
    pending: List = field(init=False)
    scans: List = field(init=False)
    plugins: Dict = field(init=False)

    def __post_init__(self):
        """Initialize mutable attributes after __init__."""
        self.results = []
        self.pending = []
        self.scans = []
        self.plugins = {}
    
    def loader_plugins(self):
        p_loader.list_plugins()
        return {m: props for m, props in p_loader.list_plugins().items() if "netscan" in props["supported_modules"]}

    def setup_plugins(self, profile):
        if profile == 'full':
            return {m: props for m, props in self.loader_plugins().items() 
                    if m in ['NaabuTCPFull', 'NmapTCPFull']}
        return {m: props for m, props in self.loader_plugins().items() 
                    if m in ['NaabuTCPTop1000', 'NmapTCPTop1000']}
    
    def get_plugin(self, plugin_name):
        plugins = self.loader_plugins()
        return {m: props for m, props in plugins.items() if plugin_name in props["name"]}
    
    def setup_scan_sslplugins(self, service):
        return {m: props for m, props in self.loader_plugins().items() 
                if "scans" in props["tag"] and (re.search('|'.join(props["services_matches"]), service)) or m == 'SSLScan'}
    
    def setup_scan_plugins(self, service):
        return {m: props for m, props in self.loader_plugins().items() 
                if "scans" in props["tag"] and re.search('|'.join(props["services_matches"]), service) and m != 'SSLScan'}
        
    def check_run_once(self, plug, props):
        if props['run_once'] == True:
            if (plug,) in self.scans:
                return False
            else:
                self.scans.append(tuple([plug]))
                return True
        else:
            return True
    
    def guess_services_by_port(self, port):
        """Guess service by port number with improved tcpwrapped handling"""
        # Convert port to string for consistent comparison
        port_str = str(port)
    
        insecure_ports = {
            '20':'ftp', '21':'ftp', '22':'ssh', '23':'telnet', '25':'smtp', '53':'domain', 
            '69':'tftp', '79':'finger', '80':'http', '88':'kerberos', '109':'pop3', '110':'pop3', 
            '111':'rpcbind', '119':'nntp', '135':'msrpc', '139':'netbios-ssn', '143':'imap', 
            '161':'snmp', '220':'imap', '389':'ldap', '433':'nntp', '445':'smb', '587':'smtp', 
            '631':'ipp', '873':'rsync', '1098':'java-rmi', '1099':'java-rmi', '1433':'mssql', 
            '1521':'oracle', '2049':'nfs', '2483':'oracle', '3020':'smb', '3306':'mysql', 
            '3389':'rdp', '3632':'distccd', '5060':'asterisk', '5500':'vnc', '5900':'vnc', 
            '5985':'wsman', '6379':'redis', '8080':'http-proxy', '27017':'mongod', 
            '27018':'mongod', '27019':'mongod'
        }
    
        secure_ports = {
            '443':'https', '465':'smtp', '563':'nntp', '585':'imaps', '593':'msrpc', 
            '636':'ldap', '989':'ftp', '990':'ftp', '992':'telnet', '993':'imaps', 
            '995':'pop3s', '2484':'oracle', '5061':'asterisk', '5986':'wsman'
        }
    
        # Check insecure ports first
        if port_str in insecure_ports:
            return insecure_ports[port_str]
    
        # Check secure ports
        if port_str in secure_ports:
            return f"ssl/{secure_ports[port_str]}"
    
        # Return None if no match found
        return None
    
    def is_tcpwrapped_service(self, service):
        """Check if service indicates tcpwrapped with multiple detection methods"""
        if not service:
            return False
    
        service_lower = service.lower()
    
        # Multiple ways tcpwrapped might appear
        tcpwrapped_indicators = [
            'tcpwrapped',
            'tcp-wrapped', 
            'tcp_wrapped',
            'wrapped'
        ]
    
        # Exact match or contains tcpwrapped
        return (service_lower in tcpwrapped_indicators or 
                any(indicator in service_lower for indicator in tcpwrapped_indicators))

    async def services_scan(self, protocol: str, port: int, service:str)-> None:

        """Scan services with improved tcpwrapped handling"""
    
        debug("Starting NetScan scanning {bmagenta}{service}:{port}{rst} on: {byellow}{target}{rst}", 
              target=self.target, service=service, port=port)
    
        original_service = service
    
        # Improved tcpwrapped detection and handling
        if self.is_tcpwrapped_service(service):
            info("Detected tcpwrapped service on port {port}, attempting to guess actual service", 
                  port=port)
        
            guessed_service = self.guess_services_by_port(port)
        
            if guessed_service:
                service = guessed_service
                debug("Guessed service for port {port}: {bgreen}{service}{rst} (was: {original})", 
                      port=port, service=service, original=original_service)
            else:
                error("Could not guess service for tcpwrapped port {port}, using original: {service}", 
                        port=port, service=original_service)
                
                # service = f"unknown-tcpwrapped-{port}"
        
        secure = any(x in service.lower() for x in ['ssl', 'tls', 'https'])
        
        if secure != True:
            scan_plugins = self.setup_scan_plugins(service)    
        
        if service.startswith('ssl/') or service.startswith('tls/'):
            if service[4:] == 'http':
                service = 'https'
            else:    
                service = service[4:]
            
            scan_plugins = self.setup_scan_sslplugins(service)
            
        for plug, props in scan_plugins.items():
            if not self.check_run_once(plug=plug, props=props):
                continue

            module = props['supported_modules'][0]
            props["tag"].append(self.target)
            props["tag"][1] = f"{props["tag"][1]}:{protocol}/{port}/{service}"
                    
            plugin = p_loader.load_plugin(props["path"])
            try:
                debug("Plugin instance initialized: {bgreen}{plugin}{rst}", plugin=plug)
                self.pending.add(asyncio.create_task(plugin.run(
                        target=self.target,
                        output = self.basedir,
                        tag = props["tag"],
                        service = service,
                        protocol = protocol,
                        port = port,
                        module = module)
                    )
                )
            except Exception as e:
                error("Plugin Scans{plugin} failed on {target}: {_e}", 
                        plugin=plug, target=self.target, _e=str(e))
    
    async def portscan(self):

        debug("Starting NetScan Enumeration on target: {byellow}{target}{rst}", target=self.target)
        
        for plug, props in self.plugins.items():
            if not self.check_run_once(plug=plug, props=props):
                continue
            
            props["tag"].append(self.target)
            plugin = p_loader.load_plugin(props["path"])
            module = props['supported_modules'][0]
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
                error("Plugin PortScan {plugin} failed: {_e}", 
                    plugin=plug, _e=str(e))

    async def update_results(self, service):
        if service not in self.results:
            extra_str = ' '.join(str(item) for item in service[3:] if item and str(item).strip())

            info('Found on {byellow}{target}{rst}: {bmagenta}{proto}/{port}/{service} {extra}{rst}',
                    target=self.target, proto=service[0], port=service[1], service=service[2], extra=extra_str)
            
            _service = (service[0], service[1], service[2])
            self.results.append(_service)
            return _service
        else:
            return None, None, None
    
    async def execute_async(self):
        """Async execution for PORTSCAN"""

        await self.portscan()
        
        while self.pending:

            done, self.pending = await asyncio.wait(self.pending, return_when=FIRST_COMPLETED)

            for task in done:
                try:
                    result = task.result()

                    if not isinstance(result, dict):
                        self.debug('Skipping non-dict task result: {result}', result=result)
                        continue

                    if result.get('returncode') == 0 and result.get('name') == 'portscan':
                        for service_tuple in result['matches']:
                            update_results = await self.update_results(service_tuple)
                            
                            try:
                                protocol, port, service = update_results
                                if self.only_portscan == True:
                                    #info('Running only osint recon for {byellow}{target}{rst}', target=self.target)
                                    continue

                                if not protocol and not port and not service:
                                    continue
                                
                                info('Found {bmagenta}{service}{rst} on {bmagenta}{protocol}/{port}{rst} on target {byellow}{target}{rst}',
                                     service=service, protocol=protocol, port=port, target=self.target)
                                
                                await self.services_scan(protocol=protocol, port=port, service=service)

                            except (TypeError, ValueError) as e:
                                error('Error unpacking update_results: {_e}. Result: {result}', 
                                        _e=str(e), result=result)
                                continue

                            #await self.scan_services(semaphore, service=service, protocol=protocol, port=port)                        
                except AttributeError as e:
                    self.error('Attribute error in task result: {_e}', _e=str(e))
                except Exception as e:
                    self.error('Error processing task result: {_e}', _e=str(e))

        
    
    async def execute(self, target, args):
        """Main execution method"""
        self.target = target

        start_time = time.time()

        try:
            if args.only_portscan:
                self.only_portscan = True

            if args.profile in ('default', 'full'):
                self.plugins = self.setup_plugins(args.profile)
            elif args.plugin:
                self.plugins = self.get_plugin(args.plugin)    
            

            self.basedir = os.path.abspath(os.path.join(args.outputdir, self.target))
            os.makedirs(self.basedir, exist_ok=True)
            
            scan_dir = str(os.path.abspath(os.path.join(self.basedir, 'scans')))
            os.makedirs(scan_dir, exist_ok=True)
            
            if not args.only_scans_dir:
                subdirs = ['scans/xml', 'scans/gnmap']
                for subdir in subdirs:
                    full_path = os.path.abspath(os.path.join(self.basedir, subdir))
                    os.makedirs(full_path, exist_ok=True)

            # Execute the async operations
            await self.execute_async()
            return info("NetScan reconnaissance against {byellow}{target}{rst} finished successfully in {time}", 
                        target=target, time=calculate_elapsed_time(start_time))
            
        except Exception as e:
            error("NetScan error for {target}: {_e}", target=target, _e=str(e))
            return error("NetScan Error: {target}")