"""ldapsearch-anonymous scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class LdapsearchAnonymous:
    """Scan ldap services"""
    name: str = "LdapsearchAnonymous"
    description: str = "ldap scanning with ldapsearch-anonymous"
    tag: List[str] = field(default_factory=lambda: ["scans", "LdapsearchAnonymous"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^ldap',))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):

            
        """Run ldapsearch-anonymous scan."""
        cmd = f"ldapsearch -x -H ldap://{target}:{port} -b \"dc=*******,dc=***\" \"(objectClass=*)\" | tee {output}/scans/{protocol}_{port}_{service}_ldapsearch.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
