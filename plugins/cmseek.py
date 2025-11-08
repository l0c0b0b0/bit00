"""CMSeek scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Cmseek:
    """Scan http services"""
    name: str = "Cmseek"
    description: str = "http scanning with CMSeek"
    tag: List[str] = field(default_factory=lambda: ["scans", "Cmseek"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^http','^https'))
    run_once: bool = False


    async def run(target, tag, output, service, protocol, port, module):
            
        """Run CMSeek scan."""
        cmd = f"cmseek --batch --follow-redirect --url {service}://{target}:{port} 2>&1 | tee {output}/scans/{protocol}_{port}_{service}_CMSeek.ansi; cmseek --clear-result"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
