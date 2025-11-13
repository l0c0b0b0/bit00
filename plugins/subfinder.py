"""SubFinder reconnaissance plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class SubFinder:
    name: str = "SubFinder"
    description: str = "SubFinder subdomain reconnaissance and enumeration"
    tag: List[str] = field(default_factory=lambda: ["discover", "SubFinder"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = False

    async def run(target, tag, output, module):

        cmd = f"/usr/bin/subfinder -d {target} | tee {output}/scans/recon/subfinder_{target}.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)

 