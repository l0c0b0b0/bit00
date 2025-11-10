"""DNS reconnaissance plugin."""
import os
from dataclasses import dataclass, field
from typing import List, Tuple
from core.runcmd import runcommand

@dataclass
class ScrapingGitHub:
    name: str = "ScrapingGitHub"
    description: str = "ScrapingGitHub search for password in public GitHub repositories"
    tag: List[str] = field(default_factory=lambda: ["subdomain", "ScrapingGitHub"])
    supported_modules: List[str] = field(default_factory=lambda: ["osint"])
    services_matches: Tuple[str, ...] = field(default_factory=tuple)
    run_once: bool = True

    
    async def run(target, tag, output, module):
        _tmp = target.split('.')[0]
        sh_script = f'''#!/bin/sh
SEARCH_WORDS="{target} {_tmp}"
for word in $SEARCH_WORDS; do
    echo "=== Searching for: $word ==="
    
    curl -s "https://api.github.com/search/repositories?q=$word&sort=stars&order=desc&per_page=10" | \\
    jq -r '.items[] | "\\(.full_name) \\(.clone_url)"' | \\
    while read repo_name clone_url; do
        if [ -n "$repo_name" ]; then
            echo "Report Name: $repo_name"
            TEMP_DIR="/tmp/GITrepo_$(echo "$repo_name" | tr '/' '_')"
	    echo "Cloning: $clone_url"
            git clone --depth 1 "$clone_url" "$TEMP_DIR" 2>/dev/null
            
            if [ -d "$TEMP_DIR" ]; then
                echo "Scanning: $repo_name"
                
                # Search for REAL passwords (exclude libraries and login forms)
		echo "=== Potential hardcoded passwords ==="
		find "$TEMP_DIR" -type f \\( -name ".env" \\
			-o -name "*.config" \\
			-o -name "*.properties" \\
		       	-o -name "config.*" \\
			-o -name "*.json" \\
			-o -name "*.yml" \\
			-o -name "*.yaml" \\
			-o -name "script.*" \\
			-o -name "scripts.*" \\
			-o -name "secrets.*" \\
			-o -name "credentials.*" \\
			-o -name "credential.*" \\) \\
			-not -path "*/node_modules/*" \\
			-not -path "*/vendor/*" \\
			-not -path "*/.git/*" \\
			-not -path "*/js/*" \\
            -not -path "*/axa_policy_doc/*" \\
                  -exec grep -H -n -E -a "( \\
		  password =|password|username =|username|users|usr|passwd|pwd|secret|api_key|secret_key|private_key|root|email| \\
		  dbname|dbpassword|database_username|database_name|database_password|mysql_password|postgres_password \\
		  )" {{}} \\; 2>/dev/null
                
                rm -rf "$TEMP_DIR"
                echo "Cleaned up: $repo_name"
            fi
            echo "---"
        fi
    done
    sleep 1
done
'''
    
        # Write to temporary file
        script_path = "/tmp/scraping_github.sh"
        with open(script_path, 'w') as f:
            f.write(sh_script)
    
        os.chmod(script_path, 0o755)

        cmd = f"/usr/bin/sh {script_path} | tee {output}/scans/info/github_scraping_{target}.txt && rm -rf {script_path} "
        
        return await runcommand(cmd=cmd, tag=tag, output=output, module=module)
        