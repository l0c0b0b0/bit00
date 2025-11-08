"""nmap-telnet scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapTelnet:
    """Scan telnet services"""
    name: str = "NmapTelnet"
    description: str = "telnet scanning with nmap-telnet"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapTelnet"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^telnet',))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-telnet scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,telnet-encryption,telnet-ntlm-info\" -oN {output}/scans/{protocol}_{port}_telnet-nmap.txt -oX {output}/scans/xml/{protocol}_{port}_telnet_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
