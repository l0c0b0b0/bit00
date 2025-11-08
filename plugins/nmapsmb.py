"""nmap-smb scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapSmb:
    """Scan smb services"""
    name: str = "NmapSmb"
    description: str = "smb scanning with nmap-smb"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapSmb"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^smb', '^microsoft-ds', '^netbios'))
    run_once: bool = False
        
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-smb scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" --script-args=\"unsafe=1\" -oN {output}/scans/{protocol}_{port}_smb_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_smb_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
