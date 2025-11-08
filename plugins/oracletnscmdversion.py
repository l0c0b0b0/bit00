"""oracle-tnscmd-version scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class OracleTnscmdVersion:
    """Scan oracle services"""
    name: str = "OracleTnscmdVersion"
    description: str = "oracle scanning with oracle-tnscmd-version"
    tag: List[str] = field(default_factory=lambda: ["scans", "OracleTnscmdVersion"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^oracle',))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run oracle-tnscmd-version scan."""
        cmd = f"tnscmd10g version -h {target} -p {port} 2>&1 | tee {output}/scans/{protocol}_{port}_oracle_tnscmd_version.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
