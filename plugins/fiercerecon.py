"""DNS reconnaissance plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class FirceRecon:
    """Fierce DNS enumeration using Fierce."""
    name: str = "FirceRecon"
    description: str = "Fierce DNS reconnaissance and enumeration"
    # discover, revlookup, info, subdomain, ipnet
    tag: List[str] = field(default_factory=lambda: ["discover", "FirceRecon"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = False
    
    async def run(target, tag, output, module):

        cmd = f"/usr/bin/fierce --domain {target} | tee {output}/scans/recon/dns_fierce_{target}.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)

 