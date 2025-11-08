"""impacket-rpcdump scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class ImpacketRpcdump:
    """Scan rpc services"""
    name: str = "ImpacketRpcdump"
    description: str = "rpc scanning with impacket-rpcdump"
    tag: List[str] = field(default_factory=lambda: ["scans", "ImpacketRpcdump"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^msrpc', '^rpcbind', '^erpc'))
    run_once: bool = False
          
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run impacket-rpcdump scan."""
        cmd = f"impacket-rpcdump -port {port} {target} | tee {output}/scans/{protocol}_{port}_rpc_rpcdump.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
