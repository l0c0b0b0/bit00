"""Sublister Email reconnaissance plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class SpiderfootEmail:
    name: str = "SpiderfootEmail"
    description: str = "Spiderfoot Email reconnaissance tool"
    tag: List[str] = field(default_factory=lambda: ["subdomain", "SpiderfootEmail"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = True
    
    async def run(target, tag, output, module):

        cmd = f"/usr/bin/spiderfoot -t EMAILADDR,EMAILADDR_COMPROMISED,EMAILADDR_DELIVERABLE,EMAILADDR_GENERIC,MALICIOUS_EMAILADDR -x -q -r -s {target} | tee {output}/scans/info/email_spiderfoot_{target}.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
        

  