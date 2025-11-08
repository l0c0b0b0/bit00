"""nmap-distcc scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapDistcc:
    """Scan distcc services"""
    name: str = "NmapDistcc"
    description: str = "distcc scanning with nmap-distcc"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapDistcc"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^distccd',))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module):

            
        """Run nmap-distcc scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,distcc-cve2004-2687\" --script-args=\"distcc-cve2004-2687.cmd=id\" -oN {output}/scans/{protocol}_{port}_distcc_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_distcc_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
