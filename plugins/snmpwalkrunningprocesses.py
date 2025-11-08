"""snmpwalk-running-processes scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class SnmpwalkRunningProcesses:
    """Scan snmp services"""
    name: str = "SnmpwalkRunningProcesses"
    description: str = "snmp scanning with snmpwalk-running-processes"
    tag: List[str] = field(default_factory=lambda: ["scans", "SnmpwalkRunningProcesses"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^snmp',))
    run_once: bool = True
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run snmpwalk-running-processes scan."""
        cmd = f"snmpwalk -c public -v 2c {target} 1.3.6.1.2.1.25.4.2.1.2 2>&1 | tee {output}/scans/{protocol}_{port}_snmp_snmpwalk_processes.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
