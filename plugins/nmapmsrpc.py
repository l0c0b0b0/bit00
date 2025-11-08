"""nmap-msrpc scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NmapMsrpc:
    """Scan rpc services"""
    name: str = "NmapMsrpc"
    description: str = "rpc scanning with nmap-msrpc"
    tag: List[str] = field(default_factory=lambda: ["scans", "NmapMsrpc"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^msrpc', '^rpcbind', '^erpc'))
    run_once: bool = False
    
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run nmap-msrpc scan."""
        cmd = f"nmap -vv -Pn -sV -p {port} --script=\"banner,msrpc-enum,rpc-grind,rpcinfo\" -oN {output}/scans/{protocol}_{port}_rpc_nmap.txt -oX {output}/scans/xml/{protocol}_{port}_rpc_nmap.xml {target}"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
