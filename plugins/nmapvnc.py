"""nmap-vnc scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapVnc:
    """Scan vnc services"""
    name: str = "NmapVnc"
    description: str = "vnc scanning with nmap-vnc"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapVnc"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^vnc',))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-vnc scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(vnc* or realvnc* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" --script-args=\"unsafe=1\" -oN {output}/scans/{protocol}_{port}_vnc_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_vnc_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
