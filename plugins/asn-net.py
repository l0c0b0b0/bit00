"""DNS reconnaissance plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class AsnNet:
    name: str = "AsnNet"
    description: str = "AsnNet CVE and Tech reconnaissance"
    tag: List[str] = field(default_factory=lambda: ["ipnet", "AsnNet"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = False
        
    async def run(target, tag, output, module):

        cmd = f"/usr/bin/asn -s -m -J {target} | tee {output}/scans/tech/net_asn_{target}.json"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
        

  