"""nmap-redis scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapRedis:
    """Scan redis services"""
    name: str = "NmapRedis"
    description: str = "redis scanning with nmap-redis"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapRedis"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^redis$',))
    run_once: bool = False
        
       
    async def run(target, tag, output, service, protocol, port, module):
    
            
        """Run nmap-redis scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,redis-info\" -oN {output}/scans/{protocol}_{port}_redis_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_redis_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
