"""DNS reconnaissance plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class SublisterPorts:
    """Sublist3r enumeration TCP ports."""
    name: str = "SublisterPorts"
    description: str = "Sublist3r TCP Port reconnaissance"
    tag: List[str] = field(default_factory=lambda: ["ipnet", "SublisterPorts"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = False

    
    async def run(target, tag,output, module):
        
        cmd  = f"/usr/bin/sublist3r --verbose --no-color --ports 21,22,23,25,53,80,110,111,135,139,143,199,443,445,587,993,995,1025,1720,1723,3306,3389,5900,8080,8888 --domain {target} -o {output}/scans/recon/subdomains_sublist3r_{target}.txt"

        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
