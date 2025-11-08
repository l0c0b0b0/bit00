"""nmap-ftp scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapFtp:
    """Scan ftp services"""
    name: str = "NmapFtp"
    description: str = "ftp scanning with nmap-ftp"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapFtp"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^ftp', '^ftp-data'))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-ftp scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(ftp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" -oN {output}/scans/{protocol}_{port}_ftp_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_{service}_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
