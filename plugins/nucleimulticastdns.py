"""nmap-multicastdns scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NucleiMulticastdns:
    """Scan multicastdns services"""
    name: str = "NucleiMulticastdns"
    description: str = "multicastdns scanning with nmap-multicastdns"
    tag: List[str] = field(default_factory=lambda: ["scans", "NucleiMulticastdns"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^mdns', '^zeroconf'))
    run_once: bool = False
        
   
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-multicastdns scan."""
        cmd = f"/usr/bin/nuclei -no-color -silent -no-interactsh -target {target} -tags mdns, zeroconf -rate-limit 50 -concurrency 5 -retries 2 -max-host-error 2 -o -o {output}/scans/{protocol}_{port}_{service}_nuclei.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
