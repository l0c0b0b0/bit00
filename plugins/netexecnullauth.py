"""netexec-nullauth scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NetexecNullauth:
    """Scan smb services"""
    name: str = "NetexecNullauth"
    description: str = "smb scanning with netexec-nullauth"
    tag: List[str] = field(default_factory=lambda: ["scans", "NetexecNullauth"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^smb', '^microsoft\-ds', '^netbios'))
    run_once: bool = True
        
   
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run netexec-nullauth scan."""
        cmd = f"netexec smb {target} -u '' -p '' --log '{output}/scans/{protocol}_{port}_smb_netexec_nullauth.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
