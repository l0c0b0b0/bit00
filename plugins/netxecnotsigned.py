"""netxec-notsigned scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NetxecNotsigned:
    """Scan ldap services"""
    name: str = "NetxecNotsigned"
    description: str = "ldap scanning with netxec-notsigned"
    tag: List[str] = field(default_factory=lambda: ["scans", "NetxecNotsigned"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^ldap',))
    run_once: bool = False
        
   
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run netxec-notsigned scan."""
        cmd = f"netexec ldap {target} -M ldap-checker --log {output}/scans/{protocol}_{port}_{service}_netexec_notsigned.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
