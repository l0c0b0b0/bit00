"""nmap-pop3 scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapPop3:
    """Scan pop3 services"""
    name: str = "NmapPop3"
    description: str = "pop3 scanning with nmap-pop3"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapPop3"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^pop3', '^pop3s'))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-pop3 scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(pop3* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" -oN {output}/scans/{protocol}_{port}_pop3_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_pop3_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
