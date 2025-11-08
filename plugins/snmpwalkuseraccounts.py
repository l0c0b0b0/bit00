"""snmpwalk-user-accounts scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class SnmpwalkUserAccounts:
    """Scan snmp services"""
    name: str = "SnmpwalkUserAccounts"
    description: str = "snmp scanning with snmpwalk-user-accounts"
    tag: List[str] = field(default_factory=lambda: ["scans", "SnmpwalkUserAccounts"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^snmp',))
    run_once: bool = True
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run snmpwalk-user-accounts scan."""
        cmd = f"snmpwalk -c public -v 2c {target} 1.3.6.1.4.1.77.1.2.25 2>&1 | tee {output}/scans/{protocol}_{port}_snmp_snmpwalk_users.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
