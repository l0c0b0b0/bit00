"""nmap-irc scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NucleiIrc:
    """Scan imap services"""
    name: str = "NucleiIrc"
    description: str = "imap scanning with nuclei-irc"
    tag: List[str] = field(default_factory=lambda: ["scans", "NucleiIrc"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^imap', '^irc'))
    run_once: bool = False
           
    async def run(target, tag, output, service, protocol, port, module):
     
            
        """Run nmap-irc scan."""
        cmd = f"/usr/bin/nuclei -no-color -silent -no-interactsh -target {target} -tags imap -rate-limit 50 -concurrency 5 -retries 2 -max-host-error 2 -o -o {output}/scans/{protocol}_{port}_{service}_nuclei.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
