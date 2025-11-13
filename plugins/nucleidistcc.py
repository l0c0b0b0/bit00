"""nmap-distcc scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NucleiDistcc:
    """Scan distcc services"""
    name: str = "NucleiDistcc"
    description: str = "distcc scanning with nuclei-distcc"
    tag: List[str] = field(default_factory=lambda: ["scans", "NucleiDistcc"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^distccd',))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module):

            
        """Run nmap-distcc scan."""
        cmd = f"/usr/bin/nuclei -no-color -silent -no-interactsh -target {target} -tags distccd -rate-limit 50 -concurrency 5 -retries 2 -max-host-error 2 -o -o {output}/scans/{protocol}_{port}_{service}_nuclei.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
