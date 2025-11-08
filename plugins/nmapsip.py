"""nmap-sip scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapSip:
    """Scan sip services"""
    name: str = "NmapSip"
    description: str = "sip scanning with nmap-sip"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapSip"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^asterisk',))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-sip scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,sip-enum-users,sip-methods\" -oN {output}/scans/{protocol}_{port}_sip_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_sip_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
