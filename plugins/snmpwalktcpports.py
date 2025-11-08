"""snmpwalk-tcp-ports scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class SnmpwalkTcpPorts:
    """Scan snmp services"""
    name: str = "SnmpwalkTcpPorts"
    description: str = "snmp scanning with snmpwalk-tcp-ports"
    tag: List[str] = field(default_factory=lambda: ["scans", "SnmpwalkTcpPorts"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^snmp',))
    run_once: bool = True
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run snmpwalk-tcp-ports scan."""
        cmd = f"snmpwalk -c public -v 2c {target} 1.3.6.1.2.1.6.13.1.3 2>&1 | tee {output}/scans/{protocol}_{port}_snmp_snmpwalk_tcpports.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
