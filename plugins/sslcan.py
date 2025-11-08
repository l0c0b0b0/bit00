"""showmount scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class SSLScan:
    """Scan nfs services"""
    name: str = "SSLScan"
    description: str = "nfs scanning with showmount"
    tag: List[str] = field(default_factory=lambda: ["scans", "SSLScan"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run showmount scan."""
        cmd = f"sslscan --show-certificate --no-colour {target}:{port} 2>&1 | tee {output}/scans/{protocol}_{port}_sslscan.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
