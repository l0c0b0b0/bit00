"""Argument parser setup for NetScan module."""
import argparse

def mod_args(subparsers: argparse._SubParsersAction, parents: list) -> argparse.ArgumentParser:
    netscan_parser = subparsers.add_parser('netscan', parents=parents, description='Network reconnaissance tool to port scan and automatically enumerate services on multiple targets.')
    netscan_parser.add_argument('targets', action='store', 
                                help='IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.', nargs='*')
    netscan_parser.add_argument('--only-portscan', action='store_true', default=False, dest='only_portscan',help='Only scan open ports and ips, enumeration services will NOT run. Default: %(default)s')
    netscan_parser.add_argument('-p','--profile', action='store', default='default', dest='profile', help='The port scanning profiles: default(TCP TOP1000),full(TCP 65535). Ex.bit00.py netscan <ipaddress> -p full Default: %(default)s')
    netscan_parser.add_argument('-L', '--list-plugins', action='store_true', default=False, dest='list_plugins',
                                  help='List all available OSINT plugins')
    netscan_parser.add_argument('-P', '--plugin', action='store', type=str, default='', dest='plugin',
                                  help='Run specific plugin instead of full scan')
    netscan_parser.add_argument('-v', '--verbose', action='count', default=0,
                                help='Enable verbose output. Repeat for more verbosity.')
    netscan_parser.add_argument('-o', '--output', action='store', default='recon', dest='outputdir', help='The output directory for results. Default: %(default)s')
    netscan_parser.add_argument('--only-scans-dir', action='store_true', default=False, help='Only create the "scans" directory for results. Other directories (e.g. exploit, loot, report) will not be created. Default: false')

    return subparsers