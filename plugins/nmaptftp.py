"""nmap-tftp scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapTftp:
    """Scan tftp services"""
    name: str = "NmapTftp"
    description: str = "tftp scanning with nmap-tftp"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapTftp"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^tftp',))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-tftp scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,tftp-enum\" -oN {output}/scans/{protocol}_{port}_tftp-nmap.txt -oX {output}/scans/xml/{protocol}_{port}_tftp_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
