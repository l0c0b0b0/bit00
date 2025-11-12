"""Nmap scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapTCPTop1000:
    """Top 1000 TCP Ports"""
    name: str = "NmapTCPTop1000"
    description: str = "Performs an Nmap scan of the top 1000 TCP ports."
    # discover, revlookup, info, subdomain, ipnet
    tag: List[str] = field(default_factory=lambda: ["portscan", "NmapTCPTop1000"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = True

    async def run(target, tag, output, module):

        """Run nmap scan."""
        cmd = f"nmap -vv -Pn --top-ports=1000 --min-rate=1000 -T4 --open -O --osscan-guess --osscan-limit --max-os-tries 5 -sV --traceroute --disable-arp-ping --source-port 53 \
-oG {output}/scans/gnmap/_top_1000_tcp_nmap.gnmap -oN {output}/scans/_top_1000_tcp_nmap.txt -oX {output}/scans/xml/_top_1000_tcp_nmap.xml {target}; \
searchsploit --nmap {output}/scans/xml/_top_1000_tcp_nmap.xml > {output}/scans/searchsploit-nmap-tcp.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
    
  