"""nmap-mysql scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapMysql:
    """Scan mysql services"""
    name: str = "NmapMysql"
    description: str = "mysql scanning with nmap-mysql"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapMysql"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^mysql',))
    run_once: bool = False
        
       
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-mysql scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" -oN {output}/scans/{protocol}_{port}_mysql_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_mysql_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
