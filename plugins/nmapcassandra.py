"""nmap-cassandra scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapCassandra:
    """Scan cassandra services"""
    name: str = "NmapCassandra"
    description: str = "cassandra scanning with nmap-cassandra"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapCassandra"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^apani1',))
    run_once: bool = False
        

    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-cassandra scan."""
        cmd = f"nmap -vv -Pn -sV  -p {port} --script=\"banner,(cassandra* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" -oN {output}/scans/{protocol}_{port}_cassandra_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_cassandra_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
