"""dig scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Dig:
    """Scan dns services"""
    name: str = "Dig"
    description: str = "dns scanning with dig"
    tag: List[str] = field(default_factory=lambda: ["scans", "Dig"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^domain',))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run dig scan."""
        cmd = f"dig -p {port} -x {target} @{target} | tee {output}/scans/{protocol}_{port}_{service}_revlookup.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
