"""nuclei scanning plugin."""
import random
import asyncio
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class Nuclei:
    """Scan http services"""
    name: str = "Nuclei"
    description: str = "http scanning with nuclei"
    tag: List[str] = field(default_factory=lambda: ["scans", "Nuclei"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = False
        
    async def run(target, tag, output, module):
        tag[1] = f"{tag[1]}:tcp/0000/full"
        sleep_time = random.randint(5, 10)
        await asyncio.sleep(sleep_time)
        """Run nuclei scan."""
        cmd = f'/usr/bin/nuclei -no-color -silent -no-interactsh -target {target} -rate-limit 50 -concurrency 5 -retries 2 -max-host-error 2 -o {output}/scans/full_nuclei.txt'
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
