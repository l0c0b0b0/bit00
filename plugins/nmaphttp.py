"""nmap-http scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapHttp:
    """Scan http services"""
    name: str = "NmapHttp"
    description: str = "http scanning with nmap-http"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapHttp"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^http',))
    run_once: bool = False
            
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-http scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)\" -oN {output}/scans/{protocol}_{port}_http_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_{service}_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
