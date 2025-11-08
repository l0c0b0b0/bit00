"""nmap-mssql scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapMssql:
    """Scan mssql services"""
    name: str = "NmapMssql"
    description: str = "mssql scanning with nmap-mssql"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapMssql"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^mssql', '^ms-sql'))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-mssql scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(ms-sql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" --script-args=\"mssql.instance-port={port},mssql.username=sa,mssql.password=sa\" -oN {output}/scans/{protocol}_{port}_mssql_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_mssql_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
