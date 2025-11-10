"""nuclei scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Nuclei:
    """Scan http services"""
    name: str = "Nuclei"
    description: str = "http scanning with nuclei"
    tag: List[str] = field(default_factory=lambda: ["scans", "Nuclei"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^http', '^https'))
    run_once: bool = True
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nuclei scan."""
        cmd = f"/usr/bin/nuclei -no-color -silent -no-interactsh -target {service}://{target}:{port}/ -rate-limit 50 -concurrency 5 -retries 2 -max-host-error 2 -o {output}/scans/{protocol}_{port}_{service}_nuclei.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
