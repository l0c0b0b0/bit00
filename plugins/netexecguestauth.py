"""netexec-guestauth scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NetexecGuestauth:
    """Scan smb services"""
    name: str = "NetexecGuestauth"
    description: str = "smb scanning with netexec-guestauth"
    tag: List[str] = field(default_factory=lambda: ["scans", "NetexecGuestauth"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^smb', '^microsoft-ds', '^netbios'))
    run_once: bool = True
        
     
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run netexec-guestauth scan."""
        cmd = f"netexec smb {target} -u 'guest' -p '' --log '{output}/scans/{protocol}_{port}_smb_netexec_guestauth.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
