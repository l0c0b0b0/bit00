"""DNSRecon reconnaissance DNS plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class DNSRegistersRecon:
    """DNS enumeration using dnsrecon."""
    name: str = "DNSRegistersRecon"
    description: str = "DNS reconnaissance."
    tag: List[str] = field(default_factory=lambda: ["scans", "DNSRegistersRecon"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^domain',))
    run_once: bool = True

    
    async def run(target, tag, output, service, protocol, port, module):

        cmd  = f"/usr/bin/dnsrecon -a -b -d {target} -c {output}/scans/{protocol}_{port}_{service}_dnsrecon.csv"

        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
