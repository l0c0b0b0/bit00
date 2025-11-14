"""nmap-imap scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapImap:
    """Scan imap services"""
    name: str = "NmapImap"
    description: str = "imap scanning with nmap-imap"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapImap"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=(r'^imap.?', '^imap-proxy', '^irc'))
    run_once: bool = False
        
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-imap scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,(imap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)\" -oN {output}/scans/{protocol}_{port}_imap_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_imap_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
