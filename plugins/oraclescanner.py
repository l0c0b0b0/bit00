"""oracle-scanner scanning plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class OracleScanner:
    """Scan oracle services"""
    name: str = "OracleScanner"
    description: str = "oracle scanning with oracle-scanner"
    tag: List[str] = field(default_factory=lambda: ["scans", "OracleScanner"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^oracle',))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
            
        """Run oracle-scanner scan."""
        cmd = f"oscanner -v -s {target} -P {port} 2>&1 | tee {output}/scans/{protocol}_{port}_oracle_scanner.txt"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
