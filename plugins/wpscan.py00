"""wpscan scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Wpscan:
    """Scan http services"""
    name: str = "Wpscan"
    description: str = "http scanning with wpscan"
    tag: List[str] = field(default_factory=lambda: ["scans", "Wpscan"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^http', '^https'))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run wpscan scan."""
        cmd = f"if [[ `cat {output}/scans/{protocol}_{port}_{service}_CMSeek.ansi | grep \"WordPress\"` ]]; then wpscan --url {service}://{target}:{port}/ --disable-tls-checks -e vp,vt,tt,cb,dbe,u,m -f cli-no-color 2>&1 | tee {output}/scans/{protocol}_{port}_{service}_wpscan.txt; fi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
