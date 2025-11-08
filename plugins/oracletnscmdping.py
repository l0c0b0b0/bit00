"""oracle-tnscmd-ping scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class OracleTnscmdPing:
    """Scan oracle services"""
    name: str = "OracleTnscmdPing"
    description: str = "oracle scanning with oracle-tnscmd-ping"
    tag: List[str] = field(default_factory=lambda: ["scans", "OracleTnscmdPing"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^oracle',))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run oracle-tnscmd-ping scan."""
        cmd = f"tnscmd10g ping -h {target} -p {port} 2>&1 | tee {output}/scans/{protocol}_{port}_oracle_tnscmd_ping.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
