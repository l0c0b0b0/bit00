"""nmap-nntp scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapNntp:
    """Scan nntp services"""
    name: str = "NmapNntp"
    description: str = "nntp scanning with nmap-nntp"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapNntp"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^nntp',))
    run_once: bool = False
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-nntp scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,nntp-ntlm-info\" -oN {output}/scans/{protocol}_{port}_nntp_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_nntp_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
