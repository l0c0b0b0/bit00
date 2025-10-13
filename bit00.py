#!/usr/bin/env python3

import argparse
import os
import sys
import signal
import psutil
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from mod._00 import CheckIO

sys.dont_write_bytecode = True

class AutoRecon(CheckIO):
    def __init__(self):
        self.modes = {}
        self.executor = None
        self.futures = []
        self.running_processes = set()  # Track running processes
        self.setup_signal_handlers()
        self.load_modes()
    
    def load_modes(self):
        """Dynamically load mode classes to avoid circular imports"""
        try:
            from mod.osint00 import OSINTRecon
            self.modes['osint'] = OSINTRecon
        except ImportError as e:
            self.warn(f"Could not load OSINT module: {e}")
        try:
            from mod.netscan00 import NetScan
            self.modes['netscan'] = NetScan
        except ImportError as e:
            self.warn(f"Could not load Scan module: {e}")
        # 
        # try:
        #     from ldap._ldap import LDAPRecon
        #     self.modes['ldap'] = LDAPRecon
        # except ImportError as e:
        #     warn(f"Could not load LDAP module: {e}")
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self._shutdown(f"Received signal {signum}")
        
    def _shutdown(self, message=""):
        """Graceful shutdown procedure"""
        self.info("Shutting down... {message}", message=message)
        
        # Terminate all running processes
        self.terminate_all_processes()
        
        # Shutdown executor
        if self.executor:
            for future in self.futures:
                future.cancel()
            self.executor.shutdown(wait=False, cancel_futures=True)
            
        sys.exit(1)
        
    def terminate_all_processes(self):
        """Terminate all child processes"""
        current_pid = os.getpid()
        
        try:
            # Get current process
            current_process = psutil.Process(current_pid)
            
            # Get all child processes
            children = current_process.children(recursive=True)
            
            if children:
                self.warn("Terminating {count} child processes...", count=len(children))
                # First try graceful termination
                for child in children:
                    try:
                        child.terminate()
                    except psutil.NoSuchProcess:
                        pass
                
                # Wait a bit for processes to terminate
                gone, still_alive = psutil.wait_procs(children, timeout=3)
                
                # Force kill any remaining processes
                for child in still_alive:
                    try:
                        child.kill()
                        self.warn("Force killed process: {pid}", pid=child.pid)
                    except psutil.NoSuchProcess:
                        pass
                        
        except Exception as e:
            self.warn("Error during process termination: {error}", error=str(e))

    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            description='Network reconnaissance tool with multiple operation modes',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s osint -t targets.txt 
  %(prog)s netscan -t targets.txt --profile quick 
  %(prog)s ldap -t targets.txt --domain example.com --username admin --password password
            """
        )
        
        subparsers = parser.add_subparsers(
            dest='mode',
            title='modes',
            description='available operation modes',
            help='choose an operation mode',
            required=True
        )
        
        # Common arguments for all modes
        common_parser = argparse.ArgumentParser(add_help=False)
        common_parser.add_argument(
            '-v', '--verbose', 
            action='count', 
            default=0, 
            help='Enable verbose output. Repeat for more verbosity.'
        )
        common_parser.add_argument(
            '-ct', '--concurrent-targets', 
            action='store', 
            metavar='<number>', 
            type=int, 
            default=5,
            help='The maximum number of target hosts to scan concurrently. Default: %(default)s'
        )
        common_parser.add_argument(
            '-cs', '--concurrent-scans', 
            action='store', 
            metavar='<number>', 
            type=int, 
            default=10,
            help='The maximum number of scans to perform per target host. Default: %(default)s'
        )
        common_parser.add_argument(
            '--disable-sanity-checks', 
            action='store_true', 
            default=False,
            help='Disable sanity checks for large target ranges'
        )
                
        # OSINT Mode Parser
        osint_parser = subparsers.add_parser('osint', parents=[common_parser], description='Perform OSINT reconnaissance to a domain')
        osint_parser.add_argument('targets', action='store', 
                                  help='Resolvable Hostname, IP addresses or CIDR notation.', nargs="*")
        osint_parser.add_argument('-t', '--targets', action='store', type=str, default='', dest='target_file', 
                                  help='Read targets from file')
        osint_parser.add_argument('-o', '--output', action='store', default='osint', dest='output_dir',
                                  help='The output directory for results. Default: %(default)s')
        osint_parser.add_argument('--only-scans-dir', action='store_true', default=False, 
                                  help='Only create the "scans" directory for results.')
        
        # Network (NetScan) Mode Parser
        netscan_parser = subparsers.add_parser('netscan', parents=[common_parser], description='Network reconnaissance tool to port scan and automatically enumerate services on multiple targets.')
        netscan_parser.add_argument('targets', action='store', 
                                help='IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.', nargs='*')
        netscan_parser.add_argument('-t', '--targets', action='store', type=str, default='', dest='target_file', 
                                help='Read targets from a file.')
        netscan_parser.add_argument('--only-portscan', action='store_true', default=False, dest='port_scan',help='Only scan open ports and ips, enumeration services will NOT run. Default: %(default)s')
        netscan_parser.add_argument('--profile', action='store', default='default', dest='profile', help='The port scanning profile the intensity of the scan there are 3 modes: default(TOP1000), full, redteam. Default: %(default)s')
        netscan_parser.add_argument('-o', '--output', action='store', default='recon', dest='output_dir', help='The output directory for results. Default: %(default)s')
        netscan_parser.add_argument('--only-scans-dir', action='store_true', default=False, help='Only create the "scans" directory for results. Other directories (e.g. exploit, loot, report) will not be created. Default: false')
        nmap_group = netscan_parser.add_mutually_exclusive_group()
        nmap_group.add_argument('--nmap', action='store', default='-vv -Pn', help='Override the {nmap_extra} variable in scans. Default: %(default)s')
        nmap_group.add_argument('--nmap-append', action='store', default='', help='Append to the default {nmap_extra} variable in scans.')
        
        
        # Add other mode parsers (scan, ldap) here...
        
        return parser.parse_args()
    
    def run(self):
        global verbose
        args = self.parse_arguments()
        verbose = args.verbose
        
        # Check if mode is available
        if args.mode not in self.modes:
            self.fail(f"Mode '{args.mode}' not available. Loaded modes: {list(self.modes.keys())}")
        
        # Process targets
        targets, errors = self.process_targets(args)
        
        # Validate concurrent settings
        if args.concurrent_targets <= 0:
            self.error('Argument -ct/--concurrent-targets: must be at least 1.')
            errors = True
            
        if args.concurrent_scans <= 0:
            self.error('Argument -cs/--concurrent-scans: must be at least 1.')
            errors = True
            
        if errors:
            self.fail("Errors found in arguments. Exiting.")
        
        self.info(f"Starting {args.mode} mode with {len(targets)} targets")
        
        # Initialize mode class
        ModeClass = self.modes[args.mode]
        
        # Run with ProcessPoolExecutor
        self.executor = ProcessPoolExecutor(max_workers=args.concurrent_targets)
        try:
            with self.executor:
                start_time = time.time()
                self.futures = []
            
                for target in targets:
                    mode_instance = ModeClass(args)
                    self.info(f"Submitted target: {target}")
                    future = self.executor.submit(mode_instance.execute, target, args.concurrent_scans)
                    self.futures.append(future)

                try:
                    for future in as_completed(self.futures):
                        try:
                            result = future.result()
                            self.debug(f"Completed target: {result}")
                        except Exception as e:
                            self.error(f"Error processing target: {e}")
                        
                except KeyboardInterrupt:
                    self._shutdown("Interrupted by user")
                        
            elapsed_time = self.calculate_elapsed_time(start_time)
            self.info('{bgreen}Finished all targets in {elapsed_time}!{rst}')
        
        except Exception as e:
            self._shutdown(f"Unexpected error: {e}")

if __name__ == '__main__':
    app = AutoRecon()
    app.run()