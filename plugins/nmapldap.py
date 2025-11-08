"""nmap-ldap scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapLdap:
    """Scan ldap services"""
    name: str = "NmapLdap"
    description: str = "ldap scanning with nmap-ldap"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapLdap"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^ldap',))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-ldap scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" -oN {output}/scans/{protocol}_{port}_ldap_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_ldap_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
