"""Argument parser for OSINT module."""
import argparse

def mod_args(subparsers, parents) -> argparse.ArgumentParser:
    """Set up OSINT module argument parser.
    
    Args:
        subparsers: Subparser group from main parser
        
    Returns:
        Configured parser for OSINT module
    """
    osint_parser = subparsers.add_parser('osint', parents=parents, description='Perform OSINT reconnaissance to a domain')
    osint_parser.add_argument('targets', action='store', 
                                help='Resolvable Hostname, IP addresses or CIDR notation.', nargs="*")
    osint_parser.add_argument('-o', '--output', action='store', default='osint', dest='outputdir',
                                help='The output directory for results. Default: %(default)s')
    osint_parser.add_argument('-oor','--only-osint-recon', action='store_true', default=False, dest='only_osintrecon', 
                                  help='Only reconnaissance phase the "scans" tools will NOT be running.')
    osint_parser.add_argument('-L', '--list-plugins', action='store_true', default=False, dest='list_plugins',
                                help='List all available OSINT plugins')
    osint_parser.add_argument('-P', '--plugin', action='store', type=str, default='', dest='plugin',
                                help='Run specific plugin instead of full scan')
    osint_parser.add_argument('-v', '--verbose', action='count', default=0,
                                help='Enable verbose output. Repeat for more verbosity.')
    osint_parser.add_argument('-r', '--results', action='store', default=False, dest='results', 
                              help='Create the report in Txt, Json and Xml. Default: It will execute after finish all targets')
    osint_parser.add_argument('--only-scans-dir', action='store_true', default=False, 
                                  help='Only create the "scans" directory for results.')
    return subparsers