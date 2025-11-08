"""nmap-kerberos scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapKerberos:
    """Scan kerberos services"""
    name: str = "NmapKerberos"
    description: str = "kerberos scanning with nmap-kerberos"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapKerberos"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^kerberos', '^kpasswd'))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-kerberos scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,krb5-enum-users\" -oN {output}/scans/{protocol}_{port}_kerberos_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_kerberos_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
