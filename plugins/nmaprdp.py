"""nmap-rdp scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapRdp:
    """Scan rdp services"""
    name: str = "NmapRdp"
    description: str = "rdp scanning with nmap-rdp"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapRdp"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^rdp', '^ms-wbt-server', '^ms-term-serv'))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-rdp scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(rdp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" -oN {output}/scans/{protocol}_{port}_rdp_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_rdp_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
