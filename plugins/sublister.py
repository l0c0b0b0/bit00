"""DNS reconnaissance plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Sublister:
    name: str = "Sublister"
    description: str = "Sublister subdomain reconnaissance and enumeration"
    tag: List[str] = field(default_factory=lambda: ["discover", "Sublister"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = False
    
    async def run(target, tag, output, module):

        cmd = f"/usr/bin/sublist3r --verbose --no-color --domain {target} -o {output}/scans/recon/sublist3r_{target}.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
        

  