"""DNS reconnaissance plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class TheHarvesterEmail:
    name: str = "TheHarvesterEmail"
    description: str = "TheHarvester Email reconnaissance tool with API keys"
    tag: List[str] = field(default_factory=lambda: ["subdomain", "TheHarvesterEmail"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = True
    
    async def run(target, tag, output, module):

        cmd = f"/usr/bin/theHarvester -b github-code,virustotal,intelx,builtwith,censys,dehashed,hunter,shodan -d {target} -f {output}/scans/info/email_theharvester_{target}.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
        

  