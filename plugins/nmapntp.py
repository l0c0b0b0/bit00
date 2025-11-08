"""nmap-ntp scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapNtp:
    """Scan ntp services"""
    name: str = "NmapNtp"
    description: str = "ntp scanning with nmap-ntp"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapNtp"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^ntp',))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-ntp scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(ntp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" -oN {output}/scans/{protocol}_{port}_ntp_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_ntp_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
