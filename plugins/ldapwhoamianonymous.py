"""ldapwhoami-anonymous scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class LdapwhoamiAnonymous:
    """Scan ldap services"""
    name: str = "LdapwhoamiAnonymous"
    description: str = "ldap scanning with ldapwhoami-anonymous"
    tag: List[str] = field(default_factory=lambda: ["scans", "LdapwhoamiAnonymous"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^ldap',))
    run_once: bool = False
        
   
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run ldapwhoami-anonymous scan."""
        cmd = f"ldapwhoami -x -H ldap://{target}:{port} | tee {output}/scans/{protocol}_{port}_{service}_ldapanonymous.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
