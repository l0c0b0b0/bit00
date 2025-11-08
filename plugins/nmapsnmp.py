"""nmap-snmp scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapSnmp:
    """Scan snmp services"""
    name: str = "NmapSnmp"
    description: str = "snmp scanning with nmap-snmp"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapSnmp"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^snmp',))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-snmp scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(snmp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" -oN {output}/scans/{protocol}_{port}_snmp_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_snmp_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
