"""SpiderFoot Web reconnaissance plugin."""
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class SpiderfootWeb:
    name: str = "SpiderfootWeb"
    description: str = "SpiderfootWeb subdomain reconnaissance Tech."
    tag: List[str] = field(default_factory=lambda: ["subdomain", "SpiderfootWeb"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = False
    
    async def run(target, tag, output, module):

        cmd = f"/usr/bin/spiderfoot -t WEBSERVER_BANNER,WEBSERVER_TECHNOLOGY,WEB_ANALYTICS_ID,TARGET_WEB_CONTENT_TYPE,TARGET_WEB_COOKIE -f -x -q -r -s {target} -o csv | tee {output}/scans/tech/web_spiderfoot_{target}.ansi"
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
        

  