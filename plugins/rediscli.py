"""redis-cli scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class RedisCli:
    """Scan redis services"""
    name: str = "RedisCli"
    description: str = "redis scanning with redis-cli"
    tag: List[str] = field(default_factory=lambda: ["scans", "RedisCli"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^redis$',))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run redis-cli scan."""
        cmd = f"redis-cli -p {port} -h {target} CONFIG GET \"*\" | tee {output}/scans/{protocol}_{port}_redis_config.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
