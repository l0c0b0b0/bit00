"""smbclient scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Smbclient:
    """Scan smb services"""
    name: str = "Smbclient"
    description: str = "smb scanning with smbclient"
    tag: List[str] = field(default_factory=lambda: ["scans", "Smbclient"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^smb', '^microsoft-ds', '^netbios'))
    run_once: bool = True
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run smbclient scan."""
        cmd = f"smbclient -L\\\\ -N -I {target} 2>&1 | tee {output}/scans/{protocol}_{port}_smb_smbclient.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
