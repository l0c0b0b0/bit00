"""snmpwalk-storage-units scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class SnmpwalkStorageUnits:
    """Scan snmp services"""
    name: str = "SnmpwalkStorageUnits"
    description: str = "snmp scanning with snmpwalk-storage-units"
    tag: List[str] = field(default_factory=lambda: ["scans", "SnmpwalkStorageUnits"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^snmp',))
    run_once: bool = True
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run snmpwalk-storage-units scan."""
        cmd = f"snmpwalk -c public -v 2c {target} 1.3.6.1.2.1.25.2.3.1.4 2>&1 | tee {output}/scans/{protocol}_{port}_snmp_snmpwalk_storage.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
