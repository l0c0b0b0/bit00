"""Run Commands with patterns."""
import re
import os
import asyncio
import socket
import time
from helpers.io import info, error, debug, e
from helpers.utils import extract_fqdn, calculate_elapsed_time
from colorama import Fore, Style
from helpers.logger import log_command, log_error, log_pattern
from loaders.patternsloaders import PatternsLoader

from core.config import SEMAPHORE, LOCK, RUNNING_TASKS


class RegexPatterns:
    def __init__(self, patterns: list):
        self.patterns = patterns
     
    def normalize_matches(match):
        _tmp = re.search(r'(?P<domain>[\w.-]+)\s+-\s+Found open ports:\s+(?P<ports>[\d,\s]+)', match)
        
        if not _tmp:
            return None, None
        
        domain = str(_tmp.group('domain'))
        ports = str(_tmp.group('ports'))
        return domain, ports
    
    async def parse_service_line(self, line: str):
        """Parse Nmap service detection line"""
        
        # Nmap service line e.g.: "80/tcp open http Microsoft IIS httpd 10.0 syn-ack ttl 125" 
        NMAP_SERVICE_LINE = re.compile(r'^(?P<port>\d+)/(?:tcp|udp)\s+\S+\s+(?P<service>[A-Za-z0-9_.+-]+)\s*(?P<version>.*)$',re.IGNORECASE)
        # TTL (syn-ack ttl 125) or (ttl 125)     
        TTL_RE = re.compile(r'(?i)(?:syn-ack\s+)?ttl\s+(?P<ttl>\d+)') 
        
        m = NMAP_SERVICE_LINE.search(line)
        if not m:
            return None
        port = m.group('port')
        service = m.group('service')
        version = (m.group('version') or '').strip()
        
        # If service is ssl/tls and version starts with a tunneled-proto token like "/http",
        # strip that token so it doesn't bleed into the version field in logs.
        if service and service.lower() in ('ssl', 'tls') and version.startswith('/'):
            version = re.sub(r'^/[A-Za-z0-9_.+-]+\s*', '', version)
        
        ttl = ''
        mt = TTL_RE.search(line)
        if mt:
            ttl = mt.group('ttl')
            version = TTL_RE.sub('', version).strip()
            # Remove possible leftover 'syn-ack' token
            version = re.sub(r'(?i)\bsyn-ack\b', '', version).strip()
        
        version = re.sub(r'\s{2,}', ' ', version)
        return port, service, version, ttl
    
    async def read_stream(self, stream, output, tag='?', color=Fore.BLUE):
        mode = tag[0]
        
        # Generate method name
        # call discover handler for both 'revlookup' and 'discover'
        if mode in ("revlookup", "discover"):
            method_name = "discover_pattern"
        elif mode in ("portscan"):
            method_name = "portscan_pattern"
        else:
            method_name = f"{mode}_pattern"

        # Check if method exists, otherwise use default
        if hasattr(self, method_name):
            method = getattr(self, method_name)
            return await method(stream, output, tag, color)
        else:
            # Fallback to default pattern matching
            return await self.default_pattern(stream, output, tag, color)
        

    async def discover_pattern(self, stream, output, tag='?', color=Fore.BLUE):
        matches = {}
        basedomain = tag[2]
        while True:
            line = await stream.readline()

            if not line:
                break

            # normalize bytes -> str
            try:
                line = str(line.strip(), 'utf8', errors='ignore')
            except UnicodeDecodeError:
                # fallback to default repr
                line = repr(line)
            
            verbose_level = int(os.getenv('SCANNER_VERBOSE', '0'))
            if verbose_level > 1:
                debug(color + '[' + Style.BRIGHT + (':'.join(tag[-2:])) + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=color, line=line)

            for p in self.patterns:
                # pattern entries may be dicts with 'pattern' key
                pat = p.get('pattern') if isinstance(p, dict) else None
                if not pat:
                    continue

                try:
                    parse_match = re.search(pat, line)
                except re.error:
                    # invalid regex; skip
                    continue
                
                if not parse_match:
                    continue

                domain_group = None
                ip_group = None
                try:
                    domain_group = parse_match.group('domain') if 'domain' in parse_match.re.groupindex else None
                except Exception:
                    domain_group = None

                try:
                    ip_group = parse_match.group('ipaddress') if 'ipaddress' in parse_match.re.groupindex else None
                except Exception:
                    ip_group = None

                _xydomain = extract_fqdn(str(domain_group) if domain_group else None)
                _ip = str(ip_group) if ip_group else None

                # Check subdomain in basedomain and not arpa domain
                if not _xydomain:
                    continue

                if 'arpa' in _xydomain:
                    continue

                if basedomain and not _xydomain.endswith(basedomain):
                    continue

                if not _ip:
                    try:
                        _ip = socket.gethostbyname(_xydomain)
                    except socket.gaierror:
                        error(f"{_xydomain} does not appear to be a resolvable hostname.")
                        continue

                # ensure we store a list of names per IP
                async with LOCK:
                    if _ip not in matches:
                        matches[_ip] = [_xydomain]
                        log_pattern(output, tag, "domain2ip", f"{_ip} => {_xydomain}")
                    elif _xydomain not in matches[_ip]:
                        matches[_ip].append(_xydomain)
                        log_pattern(output, tag, "domain2ip", f"{_ip} => {_xydomain}")
        
        return matches
    
    async def portscan_pattern(self, stream, output, tag='?', color=Fore.BLUE):
        matches = []

        while True:
            line = await stream.readline()

            if not line:
                break

            # normalize bytes -> str
            try:
                line = str(line.strip(), 'utf8', errors='ignore')
            except Exception:
                # fallback to default repr
                line = repr(line)
            
            verbose_level = int(os.getenv('SCANNER_VERBOSE', '0'))
            if verbose_level > 1:
                debug(color + '[' + Style.BRIGHT + (':'.join(tag[-2:])) + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=color, line=line)
            
            for p in self.patterns:
                pat = p.get('pattern') if isinstance(p, dict) else None
                
                if not pat:
                    continue

                try:
                    parse_match = re.search(pat, line)
                except re.error:
                    # invalid regex; skip
                    continue
                
                if not parse_match:
                    continue
                
                try:
                    proto = parse_match.group('protocol') if 'protocol' in parse_match.re.groupindex else None
                except Exception:
                    proto = None
              
                try:
                    port = int(parse_match.group('port') if 'port' in parse_match.re.groupindex else None)
                except Exception:
                    port = None

                try:
                    service = int(parse_match.group('service') if 'service' in parse_match.re.groupindex else None)
                except Exception:
                    service = None
                
                if not proto:
                    proto = 'tcp'

                _match = await self.parse_service_line(line)
                
                async with LOCK:
                    if _match:
                        _port, _service, version, ttl = _match
                        if not version and ttl:
                            srv = (proto, _port, _service, None, ttl)
                            log_pattern(output, tag, "portscan", f"{proto}/{_port}/{_service} => {ttl}")
                        
                        if not ttl and version:
                            srv = (proto, _port, _service, version, None)
                            log_pattern(output, tag, "portscan", f"{proto}/{_port}/{_service} => {version}")
                        
                        if not ttl and not version:
                            srv = (proto, _port, _service, None, None)
                            log_pattern(output, tag, "portscan", f"{proto}/{_port}/{_service}")
                        
                        srv = (proto, _port, _service, version, ttl)
                        log_pattern(output, tag, "portscan", f"{proto}/{_port}/{_service} => {version}{ttl}")
                
                if srv not in matches:
                    matches.append(srv)
            
        return matches
    
    async def default_pattern(self, stream, output, tag='?', color=Fore.BLUE):
        while True:
            line = await stream.readline()

            if not line:
                break

            # normalize bytes -> str
            try:
                line = str(line.strip(), 'utf8', errors='ignore')
            except Exception:
                # fallback to default repr
                line = repr(line)
            
            verbose_level = int(os.getenv('SCANNER_VERBOSE', '0'))
            if verbose_level > 1:
                debug(color + '[' + Style.BRIGHT + (':'.join(tag[-2:])) + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=color, line=line)

            for p in self.patterns:
                # pattern entries may be dicts with 'pattern' key
                pat = p.get('pattern') if isinstance(p, dict) else None
                desc = p.get('description') if isinstance(p, dict) else None
                if not pat:
                    continue
                try:
                    match = re.search(pat, line)
                except re.error:
                    # invalid regex; skip
                    continue
                
                if not match:
                    continue
                
                
                async with LOCK:
                    if "SublisterPorts" in tag:
                        domain, ports = self.normalize_matches(match)
                        info("Found pattern: {bgreen}{tool}:{target}:{rst}"+ "{bmagenta}" + desc.replace('{_match}') + "{rst}",
                             tool=tag[1], target=domain, _match=ports)
                        log_pattern(output, tag, desc.split(':')[0].strip(), ports)
                    
                    info("Found pattern: {bgreen}{tool}:{target}:{rst}{bmagenta}{desc}:{_match}{rst}", 
                         tool=tag[1], target=tag[2], desc=desc.split(':')[0].strip() , _match=match.group().strip('"'))
                    log_pattern(output, tag, desc.split(':')[0].strip(), match.group().strip('"'))
                
                
               
                #_matches = self.normalize_matches(parse_match)
                #for match in _matches:
                #    info('Match {bgreen}{tool}{rst} on {bgreen}{url}:{ip}{rst}: {bmagenta}' + p.get('description', '').replace('{match}', '{bblue}{match}{crst}{bmagenta}') + '{rst}', 
                #         tool=tag[1], ip=tag[2], match=match)
                    


async def runcommand(cmd, tag, output, module):
    """Generic command runner with pattern matching"""
    
    info('Running {bgreen}{tool}{rst} against: {byellow}{target}{rst}',
        tool=tag[1], target=tag[2])
        
    # Config Patterns
    if not module:
        error("No module asigned to the execute the command. {tag}")

    p_patterns = PatternsLoader(module)
    patterns = p_patterns.get_patterns_by_name(tag[0], tag[1])
    regex_pattern = RegexPatterns(patterns)


    async with SEMAPHORE:
        
        log_command(output, tag, str(cmd))
        start_time = time.time()
        process = await asyncio.create_subprocess_shell(
                cmd, 
                stdout=asyncio.subprocess.PIPE, 
                stderr=asyncio.subprocess.PIPE, 
                executable='/bin/bash'
            )
            
        async with LOCK:
            RUNNING_TASKS.append(tag)

            #return process.stdout, process.stderr

            # Use callback for specialized parsing or default pattern matching
        _output = [
            regex_pattern.read_stream(process.stdout, output=output, tag=tag),
            regex_pattern.read_stream(process.stderr, output=output, tag=tag, color=Fore.RED)
        ]
            
        #results = await self.dopattern(process, stage=stage)
        _tmp = await asyncio.gather(*_output)
        resp = _tmp[0]
        errors = _tmp[1]

        await process.wait()

        async with LOCK:
            if tag in RUNNING_TASKS:
                RUNNING_TASKS.remove(tag)

        returncode = getattr(process, 'returncode', -1)
        elapsed_time = calculate_elapsed_time(start_time)

        if returncode != 0:
            error('Task {bred}{tag}{rst} on {byellow}{target}{rst} returned non-zero exit code: {returncode}',
                      tag=tag, target=tag[2], returncode=returncode)
            async with LOCK:
                log_error(output, tag, returncode)
        else:
            info('Task {bblue}{tool}{rst} on {byellow}{target}{rst} finished successfully in {elapsed_time}',
                     tool=tag[1], target=tag[2], elapsed_time=elapsed_time)

        return {'returncode': returncode, 'name': tag[0], 'matches': resp}
