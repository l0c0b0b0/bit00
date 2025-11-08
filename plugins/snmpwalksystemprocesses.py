"""snmpwalk-system-processes scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class SnmpwalkSystemProcesses:
    """Scan snmp services"""
    name: str = "SnmpwalkSystemProcesses"
    description: str = "snmp scanning with snmpwalk-system-processes"
    tag: List[str] = field(default_factory=lambda: ["scans", "SnmpwalkSystemProcesses"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^snmp',))
    run_once: bool = True
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run snmpwalk-system-processes scan."""
        cmd = f"snmpwalk -c public -v 2c {target} 1.3.6.1.2.1.25.1.6.0 2>&1 | tee {output}/scans/{protocol}_{port}_snmp_snmpwalk_system.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
