"""nmap-vnc scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NucleiVnc:
    """Scan vnc services"""
    name: str = "NucleiVnc"
    description: str = "vnc scanning with nuclei-vnc"
    tag: List[str] = field(default_factory=lambda: ["scans", "NucleiVnc"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^vnc',))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-vnc scan."""
        cmd = f"/usr/bin/nuclei -no-color -silent -no-interactsh -target {target} -tags vnc -rate-limit 50 -concurrency 5 -retries 2 -max-host-error 2 -o -o {output}/scans/{protocol}_{port}_{service}_nuclei.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
