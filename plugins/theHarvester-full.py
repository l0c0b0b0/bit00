"""TheHarvester reconnaissance plugin."""
import os
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class TheHarvester:
    name: str = "TheHarvester"
    description: str = "TheHarvester reconnaissance tool"
    tag: List[str] = field(default_factory=lambda: ["discover", "TheHarvester"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = True
    
    async def run(target, tag, output, module):

        
        cmd = f"/usr/bin/theHarvester -b all -a -q -d {target} -f {output}/scans/info/full_theharvester_{target}.ansi"

       

        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
        

  