import asyncio
import sys
import os
import re
import time
from mod._00 import CheckIO
from colorama import Fore, Style
from concurrent.futures import FIRST_COMPLETED

sys.dont_write_bytecode = True

class NetScan(CheckIO):
    def __init__(self, args):
        super().__init__(args)
        self.netscan_variables()
    
    async def read_stream(self, stream, tag='?', color=Fore.BLUE):
        address = self.address
        
        patterns = [
            {
                'description': 'Nmap script found a potential vulnerability. ({match})',
                'pattern': r'State: (?:(?:LIKELY\_?)?VULNERABLE)'
            },
            {
                'description': 'unauthorized', 
                'pattern': r'(?i)unauthorized'
            },
            {
                'description': 'CVE Identified: ({match})',
                'pattern': r'(CVE-\d{4}-\d{4,7})'
            },
            {
                'description': 'Anonymous FTP Enabled!',
                'pattern': r'Anonymous FTP login allowed'
            }
        ]


        vuln_log_path = os.path.join(self.logdir, '_vulns.log') if self.logdir else None

        while True:
            line = await stream.readline()
            if not line:
                break

            line = str(line.rstrip(), 'utf8', 'ignore')
            self.debug(color + '[' + Style.BRIGHT + address + ' ' + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=color)

            for p in patterns:
                pat = p.get('pattern') if isinstance(p, dict) else None
                description = p.get('description', 'Pattern matched')
                if not pat:
                    continue
                try:
                    matches = re.findall(pat, line)
                except re.error:
                    # Skip invalid regexes
                    continue
        
                if not matches:
                    continue

                # Normalize matches into strings and deduplicate within the same line
                norm_matches = []
                for match in matches:
                    if isinstance(match, tuple):
                        # Prefer the first non-empty capturing group; otherwise join
                        ms = next((g for g in match if g), ' '.join(match))
                    else:
                        ms = match
                    if ms not in norm_matches:
                        norm_matches.append(ms)

                port = self.extract_port(line, tag=tag)

                for ms in norm_matches:
                    if self.verbose >= 1:
                        self.info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}{description}{rst}', 
                                 tag=tag, address=address, description=description.format(match=ms))
                    if vuln_log_path:
                        try:
                            os.makedirs(self.logdir, exist_ok=True)
                            with open(vuln_log_path, 'a') as vf:
                                vf.write(f'{address},{port},{ms}\n')
                        except Exception:
                            pass
    
    async def parse_portscan(self, stream, tag):
        """Parse port scan output"""
        ports = []
        services = []
        while True:
            line = await stream.readline()
            if line:
                line = str(line.rstrip(), 'utf8', 'ignore')
                self.debug(Fore.BLUE + '[' + Style.BRIGHT + self.address + ' ' + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', line=line)
                
                # Prefer built-in nmap parsing
                m = self.NMAP_TUPLE.search(line)
                if m:
                    proto = m.group('protocol').lower()
                    if proto == 'tcp':
                        tup = (proto, int(m.group('port')), m.group('service'))
                        if tup not in services:
                            services.append(tup)
                
                # Built-in detectors for common tools
                for rx in (self.MASSCAN_PORT, self.UNICORNSCAN_UDP_PORT, self.NMAP_TUPLE):
                    m = rx.search(line)
                    if m:
                        p = m.group('port')
                        if p not in ports:
                            ports.append(p)

                # If a full nmap service line appears during port-scan, capture summary row
                res = self.parse_service_line(line)
                if res:
                    _port, _service, _version, _ttl = res
                    # Try to capture protocol from same line; default to tcp
                    m2 = self.NMAP_TUPLE.search(line)
                    _proto = m2.group('protocol').lower() if m2 else 'tcp'
                    self.append_sumportsrv(_port, _service, _version, _ttl)
                    self.append_draft_line(_proto, _port, _service, _version, _ttl)
            else:
                break

        return ports, services

    async def run_cmd(self, semaphore, cmd, tag='?'):
        """Run a command and process its output"""
        self.info('Running task {bgreen}{tag}{rst} on {byellow}{address}{rst}', tag=tag, address=self.address)
        async with semaphore:

            with open(os.path.join(self.logdir, '_commands.log'), 'a') as file:
                file.writelines([self.e('{cmd}\n\n', cmd=cmd)])

            start_time = time.time()
            process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')
            
            # Track the process for cleanup
            self.active_processes.append(process)
            
            async with self.lock:
                self.running_tasks.append(tag)

            await asyncio.wait([
                asyncio.create_task(self.read_stream(process.stdout, tag=tag)),
                asyncio.create_task(self.read_stream(process.stderr, tag=tag, color=Fore.RED))
            ])

            await process.wait()

            # Remove from active processes
            if process in self.active_processes:
                self.active_processes.remove(process)

            async with self.lock:
                self.running_tasks.remove(tag)
            
            elapsed_time = self.calculate_elapsed_time(start_time)

        returncode = getattr(process, 'returncode', -1)
            
        if returncode != 0:
            self.error('Task {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {returncode}',
                         tag=tag, address=self.address, returncode=returncode)
            async with self.lock:
                with open(os.path.join(self.logdir, '_errors.log'), 'a') as file:
                    file.writelines([self.e('[*] Task {tag} returned non-zero exit code: {returncode}. Command: {cmd}\n', 
                                                tag=tag, returncode=returncode, cmd=cmd)])
        else:
            self.info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} finished successfully in {elapsed_time}',
                    tag=tag, address=self.address, elapsed_time=elapsed_time)

        return {'returncode': process.returncode, 'name': 'run_cmd'}
    
    async def scan_services(self, semaphore, service, protocol, port):
        # Determine if the service is secure and choose scheme accordingly
        secure = any(x in service.lower() for x in ['ssl', 'tls', 'https'])
        scheme = 'https' if secure else 'http'
                        
        # Normalize service name if it is prefixed with ssl/ or tls/

        if service.startswith('ssl/') or service.startswith('tls/'):
            service = service[4:]

        username_wordlist = self.net_scan.get('username_wordlist', '')
        password_wordlist = self.net_scan.get('password_wordlist', '')
    
        for service_scan in self.net_scan:
            # Skip special entries that aren't actual service scans
            if service_scan in ['username_wordlist', 'password_wordlist']:
                continue
            
            ignore_service = False
            if 'ignore-service-names' in self.net_scan[service_scan]:
                for ignore_service_name in self.net_scan[service_scan]['ignore-service-names']:
                    if re.search(ignore_service_name, service):
                        ignore_service = True
                        break
            
            if ignore_service:
                continue

            matched_service = False
            if 'service-names' in self.net_scan[service_scan]:
                for service_name in self.net_scan[service_scan]['service-names']:
                    if re.search(service_name, service):
                        matched_service = True
                        break
            if not matched_service:
                continue

            # Handle manual commands
            if 'manual' in self.net_scan[service_scan]:
                heading = False
                with open(os.path.join(self.scandir, '_manual_commands.txt'), 'a') as file:
                    for manual in self.net_scan[service_scan]['manual']:
                        if 'description' in manual:
                            if not heading:
                                file.writelines(self.e('[*] {service} on {protocol}/{port}\n\n'))
                                heading = True
                            description = manual['description']
                            file.writelines(self.e('\t[-] {description}\n\n'))
                        if 'commands' in manual:
                            if not heading:
                                file.writelines(self.e('[*] {service} on {protocol}/{port}\n\n'))
                                heading = True
                            for manual_command in manual['commands']:
                                manual_command = self.e(manual_command, address=self.address, scandir=self.scandir, 
                                                        port=port, protocol=protocol, scheme=scheme, nmap_extra=self.nmap_extra)
                                file.writelines('\t\t' + self.e('{manual_command}\n\n'))
                    if heading:
                        file.writelines('\n')

            # Handle automated scans
            if 'scan' in self.net_scan[service_scan]:
                for scan in self.net_scan[service_scan]['scan']:
                    if 'name' in scan:
                        name = scan['name']
                        if 'command' in scan:
                            tag = self.e('{protocol}/{port}/{name}')
                            command = scan['command']

                            if 'ports' in scan:
                                port_match = False
                                if protocol == 'tcp' and 'tcp' in scan['ports']:
                                    for tcp_port in scan['ports']['tcp']:
                                        if port == tcp_port:
                                            port_match = True
                                            break
                                elif protocol == 'udp' and 'udp' in scan['ports']:
                                    for udp_port in scan['ports']['udp']:
                                        if port == udp_port:
                                            port_match = True
                                            break
                                if not port_match:
                                    self.warn(Fore.YELLOW + '[' + Style.BRIGHT + tag + Style.NORMAL + '] Scan cannot be run against {protocol} port {port}. Skipping.' + Fore.RESET)
                                    continue

                            # Ensure {nmap_extra} is available for formatting
                            if protocol == 'udp':
                                self.nmap_extra = self.nmap + ' -sU'
                            else:
                                self.nmap_extra = self.nmap

                            # Ensure {scandir} placeholder resolves in command templates
                            
                            formatted_command = self.e(command, 
                                    address=self.address, 
                                    scandir=self.scandir,
                                    nmap_extra=self.nmap_extra,
                                    scheme=scheme,
                                    protocol=protocol,
                                    port=port)
                            
                            self.pending .add(asyncio.create_task(self.run_cmd(semaphore, cmd=formatted_command, tag=tag)))

            #self.info('Completed network scan for {byellow}{address}{rst}', address=self.address)
    
    async def scan_ports(self, semaphore, tag, port_scan):
        """Run port scanning and service detection"""
        async with semaphore:
            ports = ''
            
            ps_command = self.e(port_scan, 
                            nmap_extra=self.nmap_extra, address=self.address, scandir=self.scandir
                            )
            command = ps_command
                
            self.info('Running port scan {bgreen}{tag}{rst} on {byellow}{address}{rst}', tag=tag, address=self.address)
            with open(os.path.join(self.logdir, '_commands.log'), 'a') as file:
                file.writelines([self.e('{command}\n\n', command=command)])

            start_time = time.time()
            process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')
                
            # Track the process for cleanup
            self.active_processes.append(process)
                
            async with self.lock:
                self.running_tasks.append(tag)

            output = [
                self.parse_portscan(process.stdout, tag),
                self.read_stream(process.stderr, tag=tag, color=Fore.RED)
            ]
            
            results = await asyncio.gather(*output)
            await process.wait()

            # Remove from active processes
            if process in self.active_processes:
                self.active_processes.remove(process)

            async with self.lock:
                self.running_tasks.remove(tag)

            if process.returncode != 0:
                self.error('Port scan {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {returncode}',
                             tag=tag, address=self.address, returncode=process.returncode)
                with open(os.path.join(self.logdir, '_errors.log'), 'a') as file:
                    file.writelines([self.e('[*] Port scan {tag} returned non-zero exit code: {returncode}. Command: {command}\n',
                                            tag=tag, returncode=process.returncode, command=command)])
                return {'returncode': process.returncode}

            ports_list = results[0][0]
            ports = ','.join(ports_list) if len(ports_list) > 0 else ''
            elapsed_time = self.calculate_elapsed_time(start_time)
            self.info('Port scan {bgreen}{tag}{rst} on {byellow}{address}{rst} finished successfully in {elapsed_time}',
                        tag=tag, address=self.address, elapsed_time=elapsed_time)
            
            services = results[0][1]
            return {'returncode': process.returncode, 'name': 'scan_ports', 'services': services}
        
    async def scannet(self, semaphore):
        """Main service scanning logic"""
        self.info('Starting network scan for {byellow}{address}{rst}', address=self.address)
        
        #pending = set()
        # Use the specified mode/profile
        profile = self.profile
        if profile not in self.net_recon.keys():
            self.error('Port scan profile {profile} not found. Available profiles: {list(self.port_scan_profiles.keys())}')
            return
        self.pending = []
        for scan in self.net_recon[profile]:
            port_command = self.net_recon[profile][scan].get('command', '')

            self.pending.append(asyncio.create_task(self.scan_ports(semaphore, tag=scan, port_scan=port_command)))
            
        services_found = []

        while self.pending:

            done, self.pending = await asyncio.wait(self.pending, return_when=FIRST_COMPLETED)

            for task in done:
                try:
                    result = task.result()

                    if not isinstance(result, dict):
                        self.debug('Skipping non-dict task result: {result}', result=result)
                        continue

                    if result['returncode'] == 0 and result['name'] == 'scan_ports':
                        for service_tuple in result['services']:
                            if service_tuple not in services_found:
                                services_found.append(service_tuple)
                            else:
                                continue

                            protocol = service_tuple[0]
                            port = service_tuple[1]
                            service = service_tuple[2]

                            self.info('Found {bmagenta}{service}{rst} on {bmagenta}{protocol}/{port}{rst} on target {byellow}{address}{rst}',
                                     service=service, protocol=protocol, port=port, address=self.address)

                            await self.scan_services(semaphore, service=service, protocol=protocol, port=port)                        
                except AttributeError as e:
                    self.error('Attribute error in task result: {error}', error=str(e))
                except Exception as e:
                    self.error('Error processing task result: {error}', error=str(e))

    async def execute_async(self, concurrent_scans):
        """Async execution entry point"""
        self.lock = asyncio.Lock()
        semaphore = asyncio.Semaphore(concurrent_scans)
        
        if self.port_scan:
            self.info('Running port scan only for {byellow}{address}{rst}', address=self.address)
            # Implement port-scan only logic here if needed
        else:
            await self.scannet(semaphore)
    
    def execute(self, target, concurrent_scans):
        """Main execution method"""
        self.address = str(target)
        start_time = time.time()
        
        self.info('Scanning target {byellow}{address}{rst}', address=self.address)

        # Create directory structure
        self.basedir = os.path.abspath(os.path.join(self.output_dir, str(self.address)))
        os.makedirs(self.basedir, exist_ok=True)
        
        self.scandir = os.path.abspath(os.path.join(self.basedir, 'scans'))
        os.makedirs(self.scandir, exist_ok=True)

        self.logdir = os.path.abspath(os.path.join(self.basedir, 'logs'))
        os.makedirs(self.logdir, exist_ok=True)

        if not self.only_scans_dir:
            subdirs = ['scans/xml', 'scans/gnmap']
            for subdir in subdirs:
                full_path = os.path.abspath(os.path.join(self.basedir, subdir))
                os.makedirs(full_path, exist_ok=True)

        try:
            asyncio.run(self.execute_async(concurrent_scans))
            elapsed_time = self.calculate_elapsed_time(start_time)
            self.info('Finished scanning target {byellow}{address}{rst} in {elapsed_time}', 
                     address=self.address, elapsed_time=elapsed_time)
            return f"{self.address}"
        except KeyboardInterrupt:
            self.info("Network scan interrupted for {byellow}{address}{rst}", address=self.address)
            asyncio.run(self.cleanup_processes())
            return f"Interrupted: {self.address}"
        except Exception as e:
            self.error("Error scanning {byellow}{address}{rst}: {error}", address=self.address, error=str(e))
            import traceback
            self.debug("Full traceback: {traceback}", traceback=traceback.format_exc())
            asyncio.run(self.cleanup_processes())
            return f"Error: {self.address}"