"""nmap-oracle scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapOracle:
    """Scan oracle services"""
    name: str = "NmapOracle"
    description: str = "oracle scanning with nmap-oracle"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapOracle"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^oracle',))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-oracle scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(oracle* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" -oN {output}/scans/{protocol}_{port}_oracle_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_oracle_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
