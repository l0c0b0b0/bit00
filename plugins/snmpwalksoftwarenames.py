"""snmpwalk-software-names scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class SnmpwalkSoftwareNames:
    """Scan snmp services"""
    name: str = "SnmpwalkSoftwareNames"
    description: str = "snmp scanning with snmpwalk-software-names"
    tag: List[str] = field(default_factory=lambda: ["scans", "SnmpwalkSoftwareNames"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^snmp',))
    run_once: bool = True
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run snmpwalk-software-names scan."""
        cmd = f"snmpwalk -c public -v 2c {target} 1.3.6.1.2.1.25.6.3.1.2 2>&1 | tee {output}/scans/{protocol}_{port}_snmp_snmpwalk_software.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
