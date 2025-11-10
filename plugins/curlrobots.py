"""Curl Robots scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class CurlRobots:
    """Scan http services"""
    name: str = "CurlRobots"
    description: str = "http scanning with curl-robots"
    tag: List[str] = field(default_factory=lambda: ["scans", "CurlRobots"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^http', '^https'))
    run_once: bool = False
        
   
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run curl-robots scan."""
        cmd = f"curl -sSik {service}://{target}:{port}/robots.txt -m 10 2>&1 | tee {output}/scans/{protocol}_{port}_{service}_robots.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
