"""feroxbuster scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Feroxbuster:
    """Scan http services"""
    name: str = "Feroxbuster"
    description: str = "http scanning with feroxbuster"
    tag: List[str] = field(default_factory=lambda: ["scans", "Feroxbuster"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^http', '^https'))
    run_once: bool = False
            
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run feroxbuster scan."""
        cmd = f"feroxbuster -u {service}://{target}:{port}/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 25 -n -k -v -x txt,html,php,asp,aspx,jsp -o {output}/scans/{protocol}_{port}_{service}_feroxbuster.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
