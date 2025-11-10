"""Amass Reverse Look UP reconnaissance plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class AmassRevLookUp:
    """Amass Reverse Look UP enumeration of domains through ipaddress."""
    name: str = "AmassRevLookUp"
    description: str = "Amass Intel reconnaissance and enumeration"
    # discover, revlookup, subdomain, ipnet
    tag: List[str] = field(default_factory=lambda: ["revlookup", "AmassRevLookUp"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = True


    async def run(target, tag, output, module):
      
        cmd = f"/usr/bin/amass intel -v -max-dns-queries 500 -timeout 10 -cidr {target} -d gob.bo -o {output}/scans/recon/revlook_amass_{target}.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)

 