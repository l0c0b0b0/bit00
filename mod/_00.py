import asyncio
import sys
import string
import os
import re
import toml
import tldextract
import time
import ipaddress
from abc import ABC
from colorama import Fore, Style

sys.dont_write_bytecode = True
verbose = 0

class CheckIO(ABC):
    # Built-in regexes to avoid TOML duplication                                                                                                                                                                                                
    # Nmap service line e.g.: "80/tcp open http Microsoft IIS httpd 10.0 syn-ack ttl 125"                                                                                                                                                       
    NMAP_SERVICE_LINE = re.compile(r'^(?P<port>\d+)/(?:tcp|udp)\s+\S+\s+(?P<service>[A-Za-z0-9_.+-]+)\s*(?P<version>.*)$', re.IGNORECASE)                                                                                                       
    # Nmap tuple (protocol/port/service)                                                                                                                                                                                                        
    NMAP_TUPLE = re.compile(r'^(?P<port>\d+)/(?:)(?P<protocol>tcp|udp)\s+\S+\s+(?P<service>[A-Za-z0-9_.+-]+)\s*(?P<version>.*)$', re.IGNORECASE)                                                                                                
    # masscan: "Discovered open port 80/tcp ..."                                                                                                                                                                                                
    MASSCAN_PORT = re.compile(r'^Discovered\s+open\s+port\s*(?P<port>\d+)/(?:tcp)\b', re.IGNORECASE)                                                                                                                                            
    # unicornscan udp                                                                                                                                                                                                                           
    UNICORNSCAN_UDP_PORT = re.compile(r'^UDP\s+open\s*[\w-]+\[\s*(?P<port>\d+)\]', re.IGNORECASE)                                                                                                                                               
    # TTL (syn-ack ttl 125) or (ttl 125)                                                                                                                                                                                                        
    TTL_RE = re.compile(r'(?i)(?:syn-ack\s+)?ttl\s+(?P<ttl>\d+)') 
    TAG_PORT_RE = re.compile(r'^(?P<proto>tcp|udp)/(?P<port>\d+)')

    def __init__(self, args):
        self.args = args
        self.env()

    def env(self):
        self.address = ''
        self.type = ''
        self.basedir = ''
        self.scandir = ''
        self.logdir = ''
        self.scans = []
        self.lock = None
        self.pending = []
        self.results = dict()
        self.running_tasks = []
        self.active_processes = []
    
    def osint_variables(self):                                                                                                                                                                 
        global verbose
        self.verbose = self.args.verbose                                                                                                                                                                                                         
        verbose = self.args.verbose
        self.output_dir = self.args.output_dir                                                                                                                                                                                                   
        self.only_scans_dir = getattr(self.args, 'only_scans_dir', False)                                                                                                                                                                                                                                                                                                                                                                               
        self.osint_recon, self.osint_scan = self.check_osint_toml()
        
    
    def netscan_variables(self):
        global verbose
        self.verbose = self.args.verbose
        verbose = self.args.verbose
        self.output_dir = self.args.output_dir
        self.only_scans_dir = getattr(self.args, 'only_scans_dir', False)
        self.port_scan = getattr(self.args, 'port_scan', False)
        self.profile = getattr(self.args, 'profile', 'default')
        self.nmap_extra = getattr(self.args, 'nmap', '-vv -Pn')
        self.nmap = self.args.nmap + (f' {self.args.nmap_append}' if self.args.nmap_append else '')
        self.net_recon, self.net_scan = self.load_netscan_configs()

    async def cleanup_processes(self):
        """Clean up all running processes"""
        if self.active_processes:
            self.warn("Cleaning up {count} running processes...", count=len(self.active_processes))
            for process in self.active_processes:
                try:
                    if process.returncode is None:  # Process is still running
                        process.terminate()
                        try:
                            await asyncio.wait_for(process.wait(), timeout=5)
                        except asyncio.TimeoutError:
                            process.kill()
                            await process.wait()
                except Exception as e:
                    self.debug("Error cleaning up process: {error}", error=str(e))
            self.active_processes.clear()   
    
    # =============================================================================
    # CHECK NETSCANS TOML FILES
    # =============================================================================

    def load_netscan_configs(self):
        """Load network scan TOML configurations"""
        rootdir = os.path.dirname(os.path.realpath(__file__))
        
        # Load port scan profiles
        net_recon = os.path.join(rootdir, 'tom', 'net-recon.toml')
        if not os.path.exists(net_recon):
            self.fail(f"Port scan profiles file not found: {net_recon}")
            return {}, {}, []
        
        with open(net_recon, 'r') as f:
            try:
                net_recon = toml.load(f)
                if len(net_recon) == 0:
                    self.fail('No port scan profiles configured')
                    return {}, {}, []
            except toml.decoder.TomlDecodeError as e:
                self.fail(f'TOML syntax error in net-recon.toml: {e}')
                return {}, {}, []
        
        # Load service scans configuration
        net_scan = os.path.join(rootdir, 'tom', 'net-scan.toml')
        if not os.path.exists(net_scan):
            self.fail(f"Service scans file not found: {net_scan}")
            return {}, {}, []
        
        with open(net_scan, 'r') as f:
            try:
                net_scan = toml.load(f)
            except toml.decoder.TomlDecodeError as e:
                self.fail(f'TOML syntax error in net-scan.toml: {e}')
                return {}, {}, []
        
        return net_recon, net_scan


    # =============================================================================
    # CHECK OSINT TOML FILES
    # =============================================================================

    def check_osint_toml(self):
        rootdir = os.path.dirname(os.path.realpath(__file__))
        # osintrecon_file = 'osint-recon.toml'
        recon_path = os.path.join(rootdir, 'tom','osint-recon.toml')
        
        if not os.path.exists(recon_path):
            self.fail(f"Osint-recon.toml file not found: {recon_path}")
            return
            
        with open(recon_path, 'r') as p:
            try:
                osintrecon = toml.load(p)
                if len(osintrecon) == 0:
                    self.fail('No OSINT scan profiles configured')
                    return
                    
                for profile in osintrecon:
                    for scan in osintrecon[profile]:
                        self._validate_osint_config(profile, osintrecon[profile][scan])
                        
            except toml.decoder.TomlDecodeError as e:
                self.fail(f'TOML syntax error: {e}')
        
        
        scan_path = os.path.join(rootdir, 'tom', 'osint-scan.toml')

        if not os.path.exists(scan_path):
            self.fail(f"Osint-scan.toml file not found: {scan_path}")
            return

        with open(scan_path, 'r') as p:
            try:
                osintscan = toml.load(p)
                if len(osintscan) == 0:
                    self.fail('No OSINT scan profiles configured')
                    return

                for profile in osintscan:
                    self._validate_osint_srv(osintscan, osintscan[profile]['scan'][0])
                        
            except toml.decoder.TomlDecodeError as e:
                self.fail(f'TOML syntax error: {e}')
        
        return osintrecon, osintscan
    
    def _validate_osint_srv(self, profile, config):

        has_domain_scan = 'domain-scan' in profile
        has_ip_subdomain = 'ip-subdomain' in profile
        has_subdomain_recon = 'subdomain-recon' in profile
        has_revlookup = 'revlookup' in profile
       
        if not has_domain_scan or not has_ip_subdomain and not has_subdomain_recon and not has_revlookup:
            self.error(f'{profile} must have domain-scan, ip-subdomain, subdomain-recon and revlookup')
            return
        
        if has_domain_scan and 'command' not in config.keys():
            self.error(f'{profile}.{config} missing command')
            
            if has_ip_subdomain and 'command' not in config.keys():
                self.error(f'{profile}.{config} missing command')

            if has_subdomain_recon and 'command' not in config.keys():
                self.error(f'{profile}.{config} missing command')

            if has_revlookup and 'command' not in config.keys():
                self.error(f'{profile}.{config} missing command')

    def _validate_osint_config(self, profile, config):
        has_domain = 'domain' in profile
        has_ipaddress = 'ipaddress' in profile
        
        if not has_domain and not has_ipaddress:
            self.error(f'{profile}.{config} must have domain or ipaddress section')
            return
            
        if has_domain and 'command' not in config:
            self.error(f'{profile}.{config} missing command')
            
        if has_ipaddress and 'command' not in config:
            self.error(f'{profile}.{config} missing command')

    

    # =============================================================================
    # PROCESS TARGETS
    # =============================================================================

    def process_targets(self, args):
        """Process targets from command line and file"""
        targets = []
        errors = False
        
        # Process command line targets
        if hasattr(args, 'targets') and args.targets:
            for target in args.targets:
                is_valid, target_type, normalized = self.valid_target(target)
                if is_valid:
                    if normalized not in targets:
                        targets.append(normalized)
                    self.debug(f"Added target: {normalized} (type: {target_type})")
                else:
                    self.error(f"Invalid target: {target}")
                    errors = True
        
        # Process targets from file
        if hasattr(args, 'target_file') and args.target_file:
            if os.path.isfile(args.target_file):
                try:
                    with open(args.target_file, 'r') as f:
                        for line_num, line in enumerate(f, 1):
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue
                            is_valid, target_type, normalized = self.valid_target(line)
                            if is_valid:
                                if normalized not in targets:
                                    targets.append(normalized)
                                self.debug(f"Added target from file: {normalized} (type: {target_type})")
                            else:
                                self.error(f"Invalid target in file line {line_num}: {line}")
                                errors = True
                except OSError as e:
                    self.error(f"Could not read target file {args.target_file}: {e}")
                    errors = True
            else:
                self.error(f"Target file not found: {args.target_file}")
                errors = True
        
        if not targets:
            self.error('No valid targets specified!')
            errors = True
            
        if not args.disable_sanity_checks and len(targets) > 256:
            self.warn(f'Large number of targets: {len(targets)}. Use --disable-sanity-checks if this is intentional.')
            errors = True
            
        return targets, errors

    # =============================================================================
    # VALIDATED TARGETS
    # =============================================================================
    
    def valid_target(self, _input):
        _input = str(_input.strip())
        try:
            ip = ipaddress.ip_address(_input)
            return True, "ipaddress", ip
        except ValueError:
            pass
        
        try:
            network = ipaddress.ip_network(_input, strict=False)
            return True, "cidr", str(network)
        except ValueError:
            pass
        
        try:
            domain = tldextract.extract(_input)
            if domain.domain and domain.suffix:
                return True, "domain", _input
        except Exception:
            pass
    
        return False, "invalid", _input
    
    # =============================================================================
    # COLOR FUNCTIONS
    # =============================================================================

    def e(self, *args, frame_index=1, **kvargs):
        frame = sys._getframe(frame_index)
        vals = {}
        vals.update(frame.f_globals)
        vals.update(frame.f_locals)
        vals.update(kvargs)
        return string.Formatter().vformat(' '.join(args), args, vals)

    def cprint(self, *args, color=Fore.RESET, char='*', sep=' ', end='\n', frame_index=1, file=sys.stdout, **kvargs):
        frame = sys._getframe(frame_index)
        vals = {
            'bgreen':  Fore.GREEN  + Style.BRIGHT, 'bred':    Fore.RED    + Style.BRIGHT,
            'bblue':   Fore.BLUE   + Style.BRIGHT, 'byellow': Fore.YELLOW + Style.BRIGHT,
            'bmagenta': Fore.MAGENTA + Style.BRIGHT, 'green':  Fore.GREEN, 'red':    Fore.RED,
            'blue':   Fore.BLUE, 'yellow': Fore.YELLOW, 'magenta': Fore.MAGENTA,
            'bright': Style.BRIGHT, 'srst':   Style.NORMAL, 'crst':   Fore.RESET,
            'rst':    Style.NORMAL + Fore.RESET
        }
        vals.update(frame.f_globals)
        vals.update(frame.f_locals)
        vals.update(kvargs)

        unfmt = ''
        if char is not None:
            unfmt += color + '[' + Style.BRIGHT + char + Style.NORMAL + ']' + Fore.RESET + sep
        unfmt += sep.join(args)

        fmted = unfmt
        for attempt in range(10):
            try:
                fmted = string.Formatter().vformat(unfmt, args, vals)
                break
            except KeyError as err:
                key = err.args[0]
                unfmt = unfmt.replace('{' + key + '}', '{{' + key + '}}')

        print(fmted, sep=sep, end=end, file=file)

    def debug(self, *args, color=Fore.BLUE, sep=' ', end='\n', file=sys.stdout, **kvargs):
        if verbose >= 2:
            self.cprint(*args, color=color, char='-', sep=sep, end=end, file=file, frame_index=2, **kvargs)

    def info(self, *args, sep=' ', end='\n', file=sys.stdout, **kvargs):
        self.cprint(*args, color=Fore.GREEN, char='*', sep=sep, end=end, file=file, frame_index=2, **kvargs)

    def warn(self, *args, sep=' ', end='\n', file=sys.stderr, **kvargs):
        self.cprint(*args, color=Fore.YELLOW, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

    def error(self, *args, sep=' ', end='\n', file=sys.stderr, **kvargs):
        self.cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

    def fail(self, *args, sep=' ', end='\n', file=sys.stderr, **kvargs):
        self.cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)
        exit(-1)
    
    # =============================================================================
    # CALCULATE TIME
    # =============================================================================
    def calculate_elapsed_time(self, start_time):
        elapsed_seconds = round(time.time() - start_time)
        m, s = divmod(elapsed_seconds, 60)
        h, m = divmod(m, 60)

        elapsed_time = []
        if h == 1:
            elapsed_time.append(str(h) + ' hour')
        elif h > 1:
            elapsed_time.append(str(h) + ' hours')
        if m == 1:
            elapsed_time.append(str(m) + ' minute')
        elif m > 1:
            elapsed_time.append(str(m) + ' minutes')
        if s == 1:
            elapsed_time.append(str(s) + ' second')
        elif s > 1:
            elapsed_time.append(str(s) + ' seconds')
        else:
            elapsed_time.append('less than a second')
        return ', '.join(elapsed_time)  
    
    def extract_port(self, line_text: str, tag: str = '') -> str:
        # Prefer port embedded in the task tag (e.g., "tcp/80/…")
        if isinstance(tag, str):
            m = self.TAG_PORT_RE.search(tag)
            if m:
                return m.group('port')
        # Fallback to common scanners' outputs within the line
        for rx in (self.NMAP_TUPLE, self.MASSCAN_PORT, self.UNICORNSCAN_UDP_PORT, self.NMAP_SERVICE_LINE):
            m = rx.search(line_text)
            if m and 'port' in m.groupdict():
                return m.group('port')
        return ''
    
    def parse_service_line(self, line: str):
        """Parse Nmap service detection line"""
        m = self.NMAP_SERVICE_LINE.search(line)
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
        mt = self.TTL_RE.search(line)
        if mt:
            ttl = mt.group('ttl')
            version = self.TTL_RE.sub('', version).strip()
            # Remove possible leftover 'syn-ack' token
            version = re.sub(r'(?i)\bsyn-ack\b', '', version).strip()
        
        version = re.sub(r'\s{2,}', ' ', version)
        return port, service, version, ttl
    
    def append_sumportsrv(self, port, service, version, ttl):
        """Append service summary to CSV log"""
        log_path = os.path.join(self.logdir, '_sumportsrv.log')
        with open(log_path, 'a') as f:
            f.write(f'{self.address},{port},{service},{version},{ttl}\n')
    
    def append_draft_line(self, protocol, port, service, version, ttl):
        """Append human-readable service info to draft log"""
        ttl_part = f' ({ttl})' if ttl else ''
        draft_path = os.path.join(self.logdir, '_draft.log')
        with open(draft_path, 'a') as f:
            f.write(f'[*] {self.address}: {service} found on {protocol}/{port}: {version}{ttl_part}\n')
