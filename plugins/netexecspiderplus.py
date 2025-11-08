"""netexec-spiderplus scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NetexecSpiderplus:
    """Scan smb services"""
    name: str = "NetexecSpiderplus"
    description: str = "smb scanning with netexec-spiderplus"
    tag: List[str] = field(default_factory=lambda: ["scans", "NetexecSpiderplus"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^smb', '^microsoft\-ds', '^netbios'))
    run_once: bool = False
        
   
    async def run(target, tag, output, service, protocol, port, module):

        """Run netexec-spiderplus scan."""
        cmd = f"netexec smb {target} -u '' -p '' -M spider_plus -o OUTPUT_FOLDER='{output}/scans/' EXCLUDE_FILTER='print$,ipc$,SYSVOL,NETLOGON' &&\
            mv {output}/scans/{target}.json {output}/scans/{protocol}_{port}_smb_netexec_shares.json"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
