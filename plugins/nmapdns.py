"""nmap-dns scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapDns:
    """Scan dns services"""
    name: str = "NmapDns"
    description: str = "dns scanning with nmap-dns"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapDns"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^domain',))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module):
    
        """Run nmap-dns scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" -oN {output}/scans/{protocol}_{port}_dns_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_dns_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
