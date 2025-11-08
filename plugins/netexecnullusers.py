"""netexec-nullusers scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NetexecNullusers:
    """Scan ldap services"""
    name: str = "NetexecNullusers"
    description: str = "ldap scanning with netexec-nullusers"
    tag: List[str] = field(default_factory=lambda: ["scans", "NetexecNullusers"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^ldap',))
    run_once: bool = False
        

    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run netexec-nullusers scan."""
        cmd = f"netexec ldap {target} -u '' -p '' --users --log '{output}/scans/{protocol}_{port}_{service}_netexec_users.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
