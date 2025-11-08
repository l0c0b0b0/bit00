"""onesixtyone scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Onesixtyone:
    """Scan snmp services"""
    name: str = "Onesixtyone"
    description: str = "snmp scanning with onesixtyone"
    tag: List[str] = field(default_factory=lambda: ["scans", "Onesixtyone"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^snmp',))
    run_once: bool = True
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run onesixtyone scan."""
        cmd = f"onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt -dd {target} 2>&1 | tee {output}/scans/{protocol}_{port}_snmp_onesixtyone.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
