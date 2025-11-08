"""nbtscan scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Nbtscan:
    """Scan smb services"""
    name: str = "Nbtscan"
    description: str = "smb scanning with nbtscan"
    tag: List[str] = field(default_factory=lambda: ["scans", "Nbtscan"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^smb', '^microsoft-ds', '^netbios'))
    run_once: bool = True
        
    
    async def run(target, tag, output, service, protocol, port, module):
                  
        """Run nbtscan scan."""
        cmd = f"nbtscan -rvh {target} 2>&1 | tee {output}/scans/{protocol}_{port}_smb_nbtscan.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
