"""dig scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class DigEnum:
    """Scan dns services"""
    name: str = "DigEnum"
    description: str = "dns scanning with dig"
    tag: List[str] = field(default_factory=lambda: ["discover", "DigEnum"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = False
        
    
    async def run(target, tag, output, module):
            
        """Run dig scan."""
        cmd = f"/usr/bin/dig {target} | tee {output}/scans/recon/revdns_dig_{target}.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
