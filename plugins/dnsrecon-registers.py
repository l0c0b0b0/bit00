"""DNS reconnaissance plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class DNSReconRegisters:
    """DNS enumeration using dnsrecon."""
    name: str = "DNSReconRegisters"
    description: str = "DNS reconnaissance."
    tag: List[str] = field(default_factory=lambda: ["ipnet", "DNSReconRegisters"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint", "netscan"])
    services_matches: Tuple[str, ...] = field(default='^domain')
    run_once: bool = True

    
    async def run(target, tag, output, module):

        cmd  = f"/usr/bin/dnsrecon -a -b -d {target} -c {output}/scans/recon/revdns_dnsrecon_{target}.csv"

        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
