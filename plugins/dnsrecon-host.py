"""DNS reconnaissance plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class DNSRecon:
    """DNS enumeration using dnsrecon."""
    name: str = "DNSRecon"
    description: str = "DNS reconnaissance."
    tag: List[str] = field(default_factory=lambda: ["discover", "DNSRecon"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = False

    
    async def run(target, tag, output, module):

        cmd  = f"/usr/bin/dnsrecon -a -d {target} -c {output}/scans/recon/revdns_dnsrecon_{target}.csv"

        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
