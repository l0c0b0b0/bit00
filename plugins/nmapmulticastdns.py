"""nmap-multicastdns scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapMulticastdns:
    """Scan multicastdns services"""
    name: str = "NmapMulticastdns"
    description: str = "multicastdns scanning with nmap-multicastdns"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapMulticastdns"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^mdns', '^zeroconf'))
    run_once: bool = False
        
   
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-multicastdns scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(dns* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" -oN {output}/scans/{protocol}_{port}_multicastdns_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_multicastdns_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
