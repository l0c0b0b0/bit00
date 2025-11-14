"""Nmap scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NaabuTCPFull:
    """Full 65535 TCP Ports"""
    name: str = "NaabuTCPFull"
    description: str = "Performs an Nmap scan of the Full TCP ports 65535."
    # discover, revlookup, info, subdomain, ipnet
    tag: List[str] = field(default_factory=lambda: ["portscan", "NaabuTCPFull"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = True

    async def run(target, tag, output, module):

        """Run nmap scan."""
        cmd = f"/usr/bin/naabu -host {target} -silent -no-color -c 10 -rate 1000 --top-ports full -nmap-cli '-vv -Pn --min-rate=1000 -T4 --open -O --osscan-guess --max-os-tries 5 -sV --traceroute --disable-arp-ping --source-port 53 \
-oG {output}/scans/gnmap/_top_1000_tcp_naabunmap.gnmap -oN {output}/scans/_top_1000_tcp_naabunmap.txt -oX {output}/scans/xml/_top_1000_tcp_naabunmap.xml {target}; \
searchsploit --nmap {output}/scans/xml/_top_1000_tcp_naabunmap.xml > {output}/scans/searchsploit-naabunmap-tcp.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
    