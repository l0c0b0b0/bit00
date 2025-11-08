"""nmap-rmi scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapRmi:
    """Scan rmi services"""
    name: str = "NmapRmi"
    description: str = "rmi scanning with nmap-rmi"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapRmi"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^java-rmi', '^rmiregistry'))
    run_once: bool = False
        
       
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-rmi scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,rmi-vuln-classloader,rmi-dumpregistry\" -oN {output}/scans/{protocol}_{port}_rmi_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_rmi_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
