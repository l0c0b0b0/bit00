"""TheHarvester reconnaissance plugin."""
import os
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class TheHarvester:
    name: str = "TheHarvester"
    description: str = "TheHarvester reconnaissance tool"
    tag: List[str] = field(default_factory=lambda: ["discover", "TheHarvester"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = True
    
    async def run(target, tag, output, module):

        output_file = f"{output}/scans/info/full_theharvester.ansi"

        bash_script = f'''#!/bin/bash
# Run theHarvester
/usr/bin/theHarvester -b all -a -q -d {target} -f {output}/scans/info/full_theharvester 2>&1 | tee {output}/scans/info/full_theharvester.ansi 
if [ -f "{output_file}" ]; then
    cat "{output_file}" | \\
    awk -F: '
        NR==FNR && $2 ~ /^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$/ {{
            ip[$1] = $2
            next
        }}
        {{
            if ($2 ~ /^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$/) {{
                # Print direct IP mappings
                print $1 ":" $2
            }} else if ($2 in ip) {{
                # Resolve subdomain references
                print $1 ":" ip[$2]
            }} else {{
                print $0
            }}
        }}'
fi
'''
        # Write to temporary file
        script_path = "/tmp/theHarvester_full.sh"
        with open(script_path, 'w') as f:
            f.write(bash_script)
    
        os.chmod(script_path, 0o755)

        cmd = f"/usr/bin/bash {script_path} && rm -rf {script_path}"

        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
        

  