"""enum4linux scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Enum4linux:
    """Scan smb services"""
    name: str = "Enum4linux"
    description: str = "smb scanning with enum4linux"
    tag: List[str] = field(default_factory=lambda: ["scans", "Enum4linux"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^smb', '^microsoft-ds', '^netbios'))
    run_once: bool = True
        
    
    async def run(self, target, tag, output, service, protocol, port, module):
            
        """Run enum4linux scan."""
        cmd = f"enum4linux -a -M -l -d {target} 2>&1 | tee {output}/scans/{protocol}_{port}_smb_enum4linux.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
