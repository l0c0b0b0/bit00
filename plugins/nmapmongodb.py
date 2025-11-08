"""nmap-mongodb scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapMongodb:
    """Scan mongodb services"""
    name: str = "NmapMongodb"
    description: str = "mongodb scanning with nmap-mongodb"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapMongodb"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^mongod',))
    run_once: bool = False
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-mongodb scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(mongodb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" -oN {output}/scans/{protocol}_{port}_mongodb_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_mongodb_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
