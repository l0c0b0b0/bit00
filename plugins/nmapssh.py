"""nmap-ssh scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapSsh:
    """Scan ssh services"""
    name: str = "NmapSsh"
    description: str = "ssh scanning with nmap-ssh"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapSsh"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^ssh',))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-ssh scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods\" -oN {output}/scans/{protocol}_{port}_ssh_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_ssh_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
