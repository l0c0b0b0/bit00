"""Nmap scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapTCPFull:
    """Full 65535 TCP Ports"""
    name: str = "NmapTCPFull"
    description: str = "Performs an Nmap scan of the Full TCP ports 65535."
    # discover, revlookup, info, subdomain, ipnet
    tag: List[str] = field(default_factory=lambda: ["portscan", "NmapTCPFull"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = True

    async def run(target, tag, output, module):

        """Run nmap scan."""
        cmd = f"nmap -vv -Pn -p- --min-rate=1000 -T4 --open -O --osscan-guess --osscan-limit --max-os-tries 3 -sV --version-all --traceroute --disable-arp-ping --source-port 53 {target} \
-oG {output}/scans/gnmap/_full_tcp_nmap.gnmap -oN {output}/scans/_full_tcp_nmap.txt -oX {output}/scans/xml/_full_tcp_nmap.xml; \
searchsploit --nmap {output}/scans/xml/_full_tcp_nmap.xml > {output}/scans/searchsploit-nmap-tcp.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
    