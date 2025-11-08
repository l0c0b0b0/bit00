"""showmount scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Showmount:
    """Scan nfs services"""
    name: str = "Showmount"
    description: str = "nfs scanning with showmount"
    tag: List[str] = field(default_factory=lambda: ["scans", "Showmount"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^nfs', '^rpcbind'))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run showmount scan."""
        cmd = f"showmount -e {target} 2>&1 | tee {output}/scans/{protocol}_{port}_showmount.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
