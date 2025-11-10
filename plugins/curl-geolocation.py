"""Curl Geolocation reconnaissance plugin."""
import os
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class CurlGeolocation:
    name: str = "CurlGeolocation"
    description: str = "Curl API Geolocation reconnaissance"
    tag: List[str] = field(default_factory=lambda: ["ipnet", "CurlGeolocation"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = False

    
    async def run(target, tag, output, module):

        cmd = f"/usr/bin/curl  http://ip-api.com/json/{target} | tee {output}/scans/info/geolocation_ipapi_{target}.json"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
        

  