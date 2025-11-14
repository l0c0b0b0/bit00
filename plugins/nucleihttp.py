"""nuclei scanning plugin."""
import random
import asyncio
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class NucleiHttp:
    """Scan http services"""
    name: str = "NucleiHttp"
    description: str = "http scanning with nuclei"
    tag: List[str] = field(default_factory=lambda: ["scans", "NucleiHttp"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=('^http', '^http-proxy', '^https'))
    run_once: bool = False
        
    async def run(target, tag, output, service, protocol, port, module):
        sleep_time = random.randint(7, 15)
        await asyncio.sleep(sleep_time)
        """Run nuclei scan."""
        cmd = f'/usr/bin/nuclei -no-color -silent -no-interactsh -target {service}://{target}:{port} -t http -rate-limit 50 -concurrency 10 -retries 2 -max-host-error 2 -o {output}/scans/{protocol}_{port}_{service}_nuclei.txt'
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
