"""snmpwalk scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Snmpwalk:
    """Scan snmp services"""
    name: str = "Snmpwalk"
    description: str = "snmp scanning with snmpwalk"
    tag: List[str] = field(default_factory=lambda: ["scans", "Snmpwalk"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^snmp',))
    run_once: bool = True
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run snmpwalk scan."""
        cmd = f"snmpwalk -c public -v 2c {target} 2>&1 | tee {output}/scans/{protocol}_{port}_snmp_snmpwalk.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
