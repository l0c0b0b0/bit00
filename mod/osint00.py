import os
import sys
import re
import socket
import time
import asyncio
import tldextract
from mod._00 import CheckIO
from colorama import Fore, Style
from concurrent.futures import FIRST_COMPLETED

sys.dont_write_bytecode = True
# Import from bit00 without circular dependency by not importing at module level
# We'll import inside functions or use dependency injection

class OSINTRecon(CheckIO):
    def __init__(self, args):
        super().__init__(args)
        self.osint_variables()
        
    async def read_stream(self, stream, tag='?', patterns=[], color=Fore.BLUE):
        while True:
            line = await stream.readline()
            if line:
                line = str(line.rstrip(), 'utf8', 'ignore')
                self.debug(color + '[' + Style.BRIGHT + self.address + ' ' + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=color)

                for p in patterns:
                    matches = re.findall(p['pattern'], line)
                    if 'description' in p:
                        for match in matches:
                            if self.verbose >= 1:

                                ttool, iip, uurl = tag.split(':')
                                
                                self.info('Match {bgreen}{tool}{rst} on {bgreen}{url}:{ip}{rst}: {bmagenta}' + p['description'].replace('{match}', '{bblue}{match}{crst}{bmagenta}') + '{rst}', 
                                           tool=ttool, url=uurl, ip=iip, match=match)
                                
                            async with self.lock:
                                with open(os.path.join(self.logdir, '_patterns.log'), 'a') as file:
                                    try:
                                        # FIX: Handle different tool outputs properly
                                        if 'sublist3r' in tag:
                                            _parts = tag.split(':')
                                            if len(_parts) >= 3:
                                                _tool, _ipaddr, _subdom = _parts
                                                _flag_desc = self.e(p['description'])
                                                if ':' in _flag_desc:
                                                    _flag, _data = _flag_desc.split(':', 1)
                                                    _tmp = re.search(r'(?P<domain>[\w.-]+)\s+-\s+Found open ports:\s+(?P<ports>[\d,\s]+)', _data)
                                                    if _tmp:
                                                        _subdomm = str(_tmp.group('domain'))
                                                        _ports = str(_tmp.group('ports'))
                                                        file.write(f'[*] {_tool}:{_subdom}:{_subdomm}:{_flag}: {_ports}\n')
                                                    else:
                                                        file.write(f'[*] {tag}: {p["description"]}\n')
                                                else:
                                                    file.write(f'[*] {tag}: {p["description"]}\n')
                                        else:
                                            file.write(f'[*] {tag}:{self.e(p["description"])}\n')
                                    except Exception as e:
                                        file.write(f'[*] {tag} => Pattern match error: {str(e)}\n', tag=tag, e=e)

                    else:
                        for match in matches:
                            if self.verbose >= 1:
                                self.info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}', 
                                           tag=tag, address=self.address, match=match)
                            async with self.lock:
                                with open(os.path.join(self.logdir, '_patterns.log'), 'a') as file:
                                    file.writelines(self.e('{tag} - Matched Pattern: {match}\n',tag=tag,match=match))
            else:
                break
    
    
    async def domains_detection(self, stream, tag, pattern):
        # Check subdomains that ends at the same = _domain
        _extract = tldextract.TLDExtract()
        _domain = str(_extract(self.address).domain + '.' + _extract(self.address).suffix)

        results = {}

        while True:
            line = await stream.readline()
            if line:
                line = str(line.rstrip(), 'utf8', 'ignore')
                self.debug(Fore.BLUE + '[' + Style.BRIGHT + self.address + ' ' + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=Fore.BLUE)
                
                parse_match = re.search(pattern, line)
            
                _xydomain = str(parse_match.group('domain')) if parse_match and parse_match.group('domain') else None
                _ip = str(parse_match.group('ipaddress')) if parse_match and parse_match.group('ipaddress') else None
  
                if _xydomain and 'arpa' not in _extract(_xydomain).fqdn and not _ip:
                    if self.type != 'ipaddress' and _xydomain.endswith(_domain):
                        try:
                            _ip = socket.gethostbyname(_xydomain)
                            if _ip not in results.keys():
                                results[_ip] = [_xydomain]
                            elif _xydomain not in results[_ip]:
                                results[_ip].append(_xydomain)
                        except socket.gaierror:
                            self.error(_xydomain + ' does not appear to be a valid IP address, IP range, or resolvable hostname.')
                            self.errors = True
                            with open(os.path.join(self.logdir, '_errors.log'), 'a') as file:
                                file.writelines([self.e('[*] {target} does not appear to be a valid IP address, IP range, or resolvable hostname.\n', target=_xydomain)])
                    
                elif _xydomain and 'arpa' not in _extract(_xydomain).fqdn and _ip:
                    if self.type != 'domain':
                        if _ip not in results.keys():
                            results[_ip] = [_xydomain]
                        elif _xydomain not in results[_ip]:
                            results[_ip].append(_xydomain)
                    else:
                        if _xydomain.endswith(_domain):
                            if _ip not in results.keys():
                                results[_ip] = [_xydomain]
                            elif _xydomain not in results[_ip]:
                                results[_ip].append(_xydomain)

            else:
                break
        
        return results
    
    async def run_cmd(self, semaphore, cmd, tag='?', patterns=[]):
        
        ttool, iip, uurl = tag.split(':')

        self.info('Running task {bgreen}{ttool}{rst} on {bgreen}{iip}:{uurl}{rst}',
                   ttool=ttool, iip=iip, uurl=uurl)
        
        async with semaphore:

            async with self.lock:
                with open(os.path.join(self.logdir, '_commands.log'), 'a') as file:
                    file.writelines([self.e('{cmd}\n\n')])

            start_time = time.time()
            process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')
            
            # Track the process for cleanup
            self.active_processes.append(process)
            
            async with self.lock:
                self.running_tasks.append(tag)

            await asyncio.wait([
                asyncio.create_task(self.read_stream(process.stdout, tag=tag, patterns=patterns)),
                asyncio.create_task(self.read_stream(process.stderr, tag=tag, patterns=patterns, color=Fore.RED))
            ])

            await process.wait()

             # Remove from active processes
            if process in self.active_processes:
                self.active_processes.remove(process)

            async with self.lock:
                self.running_tasks.remove(tag)
            elapsed_time = self.calculate_elapsed_time(start_time)

        # Fix: Safe access to returncode
        returncode = getattr(process, 'returncode', -1)
        
        if returncode != 0:
            self.error('Task {bred}{ttool}{rst} on {byellow}{iip}:{uurl}{rst} returned non-zero exit code: {process.returncode}',
                         ttool=ttool, iip=iip, uurl=uurl, returncode=returncode)
            async with self.lock:
                with open(os.path.join(self.logdir, '_errors.log'), 'a') as file:
                    file.writelines([self.e('[*] Task {ttool} on {iip}:{uurl} returned non-zero exit code: {process.returncode}. Command: {cmd}\n', 
                                            ttool=ttool, iip=iip, uurl=uurl, returncode=returncode, cmd=cmd)])
        else:
            self.info('Task {bgreen}{ttool}{rst} on {byellow}{iip}:{uurl}{rst} finished successfully in {elapsed_time}',
                       ttool=ttool, iip=iip, uurl=uurl, elapsed_time=elapsed_time)

        return {'returncode': process.returncode, 'name': 'run_cmd'}    
    
    async def run_recon(self, semaphore, tag, command, pattern):

        ttool = str(tag.split(':')[0])

        command = self.e(command, address=self.address, scandir=self.scandir)
        try:
            self.info('Running recon {bgreen}{ttool}{rst} on {address}', ttool=ttool, address=self.address)
            
            async with self.lock:
                with open(os.path.join(self.logdir, '_commands.log'), 'a') as file:
                    file.writelines([self.e('{command}\n\n')])
            
            start_time = time.time()

            async with semaphore:
                process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')
            
                # Track the process for cleanup
                self.active_processes.append(process)

                async with self.lock:
                    self.running_tasks.append(tag)

                output = [
                    self.domains_detection(process.stdout, tag, pattern),
                    self.read_stream(process.stderr, tag=tag, color=Fore.RED)
                    ]
        
                results = await asyncio.gather(*output)

                await process.wait()

                # Remove from active processes (it's finished)
                if process in self.active_processes:    
                    self.active_processes.remove(process)

                async with self.lock:
                    self.running_tasks.remove(tag)
                    elapsed_time = self.calculate_elapsed_time(start_time)

                # Fix: Check if process is actually a process object
            returncode = getattr(process, 'returncode', -1)    

            if returncode != 0:
                self.error('Recon task {bred}{ttool}{rst} on {byellow}{address}{rst} returned non-zero exit code: {returncode}', 
                        ttool=ttool, address=self.address, returncode=returncode)
                
                async with self.lock:
                    with open(os.path.join(self.logdir, '_errors.log'), 'a') as file:
                        file.writelines([self.e('[*] Recon task {ttool} on {address} returned non-zero exit code: {process.returncode}. Command: {command}\n',
                                        ttool=ttool, address=self.address, returncode=process.returncode, command=command)])
                return {'returncode': process.returncode}
            else:
                self.info('Recon task {bgreen}{ttool}{rst} on {byellow}{address}{rst} finished successfully in {elapsed_time}',
                           ttool=ttool, address=self.address, elapsed_time=elapsed_time)
        

            return {'returncode': process.returncode, 'name': 'run_osintscan' , 'scans': results[0] if results else {}}
        
        except asyncio.CancelledError:
            await self.cleanup_processes()
            raise
        except Exception as e:
            self.error('Exception in run_recon for {tag}: {error}', tag=tag, error=str(e))
            return {'returncode': -1, 'name': 'run_osintscan', 'scans': {}}
    
    async def scan_osint(self, semaphore, ipaddress, domain, flag):
        for domain_scan in self.osint_scan:
            
            matched_service = False

            if 'service-names' in self.osint_scan[domain_scan]:
                for service_name in self.osint_scan[domain_scan]['service-names']:
                    if re.search(service_name,flag):
                        matched_service = True
                        break

            if not matched_service:
                continue
            
            if  'manual' in self.osint_scan[domain_scan] and domain_scan == flag:
                heading = False
                with open(os.path.join(self.scandir, '_manual_commands.txt'), 'a') as file:
                    for manual in self.osint_scan[domain_scan]['manual']:
                        if 'description' in manual:
                            if not heading:
                                file.writelines([self.e('[*] {domain} on {ipaddress}\n',
                                                 domain=domain, ipaddress=ipaddress)])
                                heading = True
                        
                            description = manual['description']
                            file.writelines([self.e('[-] {description}\n')])

                        if 'commands' in manual:
                            if not heading:
                                file.writelines(self.e('[*] {domain} on {ipaddress}\n'))
                                heading = True
                            for manual_command in manual['commands']:
                                manual_command = self.e(manual_command,address=self.address, scandir=self.scandir)
                                file.writelines(['\t' + self.e('{manual_command}\n')])    
                    
                    if heading:
                        file.writelines(['\n'])
            
            if 'scan' in self.osint_scan[domain_scan] and domain_scan == flag:
                for scan in self.osint_scan[domain_scan]['scan']:
                    if 'name' in scan.keys():
                        name = scan['name']
                        if 'command' in scan:
                            tag = self.e('{name}:{ipaddress}:{domain}')
                            command = scan['command']

                            if 'run_once' in scan.keys() and scan['run_once'] == True:
                                scan_tuple = (name,)
                                if scan_tuple in self.scans:
                                        self.warn(Fore.YELLOW + '[' + Style.BRIGHT + tag + ' on ' + domain + Style.NORMAL + '] Scan should only be run once and it appears to have already been queued. Skipping.' + Fore.RESET,
                                                   tag=tag, domain=domain)
                                        continue
                                else:
                                    self.scans.append(scan_tuple)
                                
                            else:
                                scan_tuple = (ipaddress, domain, name)
                                if scan_tuple in self.scans:
                                    self.warn(Fore.YELLOW + '[' + Style.BRIGHT + tag + ' on ' + domain + Style.NORMAL + '] Scan appears to have already been queued, but it is not marked as run_once in service-scans.toml. Possible duplicate tag? Skipping.' + Fore.RESET,
                                                   tag=tag, domain=domain)
                                    continue
                                else:
                                    self.scans.append(scan_tuple)
                                
                            patterns = []
                            if 'pattern' in scan:
                                patterns = scan['pattern']

                            # FIX: Pass all required variables to _e method
                            formatted_command = self.e(command, address=self.address, scandir=self.scandir, 
                                                     ipaddress=ipaddress, domain=domain)
                            
                              
                            self.pending.add(asyncio.create_task(self.run_cmd(semaphore, cmd=formatted_command, tag=tag, patterns=patterns)))
                             
    
        #return f"Completed scan_osint for {domain} at {ipaddress} with flag {flag}"
                                
        
    async def recon_osint(self, semaphore):
        
        self.info('Scanning OSINT for {byellow}{address}{rst}', address=self.address)
        self.type = self.valid_target(self.address)[1]

        if len(self.results) == 0 and self.type == 'domain':
            target = self.address
                
        for scan in self.osint_recon[self.type]:
            pattern = self.osint_recon[self.type][scan]['pattern']
            command = self.osint_recon[self.type][scan]['command']
            tool = scan
            
            self.pending.append(asyncio.create_task(self.run_recon(semaphore, scan, command, pattern)))
        
        while self.pending:
                
            done, self.pending = await asyncio.wait(self.pending, return_when=FIRST_COMPLETED)
        
            for task in done:
                try:
                    result = task.result()
                    if result['returncode'] == 0 and result['name'] == 'run_osintscan':
                        for _ip, _subdomains in result['scans'].items():
                            if all(isinstance(_subdomain, str) for _subdomain in _subdomains):
                                for _subdomain in _subdomains:
                                    if _ip not in self.results.keys():
                                        self.results[_ip] = [_subdomain]
                                        if _subdomain == target:
                                            flag = 'domain-scan'
                                        else:
                                            flag = 'ip-subdomain'
                                    elif _subdomain not in self.results[_ip]:
                                        self.results[_ip].append(_subdomain)
                                        flag = 'subdomain-recon'
                                                               
                                    domain = _subdomain
                                    ipaddress = _ip
                                    
                                    self.info('Found {bmagenta}{domain}{rst} at {bmagenta}{ipaddress}{rst} on target {byellow}{address}{rst}', 
                                            domain=domain, ipaddress=ipaddress, address=self.address)
                                    with open(os.path.join(self.logdir, '_domainip.csv'), 'a') as file:
                                        file.writelines(self.e('[*] {domain}:{ipaddress}\n'))
                                    
                                    
                
                                    await self.scan_osint(semaphore, ipaddress=ipaddress, domain=domain, flag=flag)

                            else:
                                self.warn('OSINT scan failed with return code: {returncode}', returncode=result['returncode'])
                    #else:
                        #self.error('Unexpected result type from task: {result_type}', result_type=type(result))
                        #self.error('Unexpected result type from task: {result}', result=result)
                    
                except AttributeError as e:
                    self.error('Attribute error in task result: {error}', error=str(e))
                except Exception as e:
                    self.error('Error processing task result: {error}', error=str(e))
        
        #return f"Completed OSINT for {self.address}"

    async def execute_async(self, concurrent_scans):
        self.lock = asyncio.Lock()
        semaphore = asyncio.Semaphore(concurrent_scans)
        await self.recon_osint(semaphore)

    def execute(self, target, concurrent_scans):
        self.address = target
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
            subdirs = ['scans/recon', 'scans/info', 'scans/tech']
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
            self.info("OSINT scan interrupted for {byellow}{address}{rst}", address=self.address)
            # Ensure cleanup happens
            asyncio.run(self.cleanup_processes())
            return f"Interrupted: {self.address}"
        except AttributeError as e:
            self.error("Attribute error scanning {byellow}{address}{rst}: {error}", address=self.address, error=str(e))
            return f"AttributeError: {self.address}"
        except Exception as e:
            self.error("Error scanning {byellow}{address}{rst}: {error}", address=self.address, error=str(e))
            import traceback
            self.debug("Full traceback: {traceback}", traceback=traceback.format_exc())
            # Ensure cleanup happens
            asyncio.run(self.cleanup_processes())
            return f"Error: {self.address}"

            