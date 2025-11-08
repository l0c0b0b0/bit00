"""nmap-irc scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapIrc:
    """Scan imap services"""
    name: str = "NmapIrc"
    description: str = "imap scanning with nmap-irc"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapIrc"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^imap', '^irc'))
    run_once: bool = False
           
    async def run(target, tag, output, service, protocol, port, module):
     
            
        """Run nmap-irc scan."""
        cmd = f"nmap -vv -Pn -sV --script irc-botnet-channels,irc-info,irc-unrealircd-backdoor -oN {output}/scans/{protocol}_{port}_irc_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_irc_nmap.xml -p {port} {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
