"""svwar scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Svwar:
    """Scan sip services"""
    name: str = "Svwar"
    description: str = "sip scanning with svwar"
    tag: List[str] = field(default_factory=lambda: ["scans", "Svwar"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^asterisk',))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run svwar scan."""
        cmd = f"svwar -D -m INVITE -p {port} {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
