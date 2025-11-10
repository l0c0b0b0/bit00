"""New Plugin scan plugin."""
import os
import asyncio
from dataclasses import dataclass, field
from typing import List, Tuple

@dataclass
class NewPlugin:

# =============================================================================
# PLUGIN METADATA - MANDATORY FIELDS FOR FRAMEWORK INTEGRATION
# =============================================================================
    # name: Must match the class name exactly (case-sensitive)
    # description: Clear description of plugin functionality
    # tag: Framework identifier [category, plugin_name]
    # supported_modules: List of modules this plugin works with ['osint', 'netscan']
    # services_matches: Service patterns for auto-detection
    #                   OSINT: leave empty tuple ()
    #                   NETSCAN: use regex patterns like ['^http', '^https']
    # run_once: Set to True for one-time execution per target
    # =============================================================================
    name: str = "NewPlugin"
    description: str = "New Plugin too develop"
    tag: List[str] = field(default_factory=lambda: ["scans", "NewPlugin"])
    supported_modules: List[str] = field(default_factory=lambda: ["netscan"])
    services_matches: Tuple[str, ...] = field(default=['^smb'])
    run_once: bool = True


    async def run(self, target, output, module=None):
        """
        =============================================================================
        MAIN PLUGIN EXECUTION METHOD
        =============================================================================
        This method is called by the framework to execute the plugin.
        
        Parameters:
        - target: The target to scan (domain, IP, etc.)
        - output: Base output directory for results
        - module: Optional module context
        
        Returns:
        - Dictionary with execution results and findings
        =============================================================================
        """
# =============================================================================
# INITIALIZATION & SETUP
# =============================================================================
        # Create the tag for this execution
        tag = self.tag + [target]
        _tmp = target.split('.')[0]

        # Create output directory if it doesn't exist
        scans_dir = os.path.join(output, "beta_plugins")
        os.makedirs(scans_dir, exist_ok=True)
# =============================================================================
# =============================================================================

# =============================================================================
#  MAIN PLUGIN METHOD - THIS IS WHAT GETS CALLED BY THE FRAMEWORK        
# =============================================================================        

        print(f"[+] Starting ScrapingGitHub plugin for target: {target}")
        
        sh_script = f'''#!/bin/sh

'''
    
        # Write to temporary file
        script_path = "/tmp/newplugin.sh"
        with open(script_path, 'w') as f:
            f.write(sh_script)
    
        os.chmod(script_path, 0o755)

        # Build the command
        output_file = os.path.join(scans_dir, f"newplugin_{target}.txt")
        cmd = f"/usr/bin/sh {script_path} | tee {output_file} && rm -rf {script_path}"

# =============================================================================
# DO NOT MODIFY THE BELOW SECCTION IS ONLY FOR DEBUG AND RUN THE COMMAND
# =============================================================================

        print(f"[+] Executing command: {cmd}")
        
        # Execute the command
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                executable='/bin/bash'
            )
            
            stdout, stderr = await process.communicate()
            returncode = process.returncode
            
            # Decode output
            stdout_text = stdout.decode('utf-8', errors='ignore') if stdout else ""
            stderr_text = stderr.decode('utf-8', errors='ignore') if stderr else ""
            
            print(f"[+] Command completed with return code: {returncode}")
            print(f"[+] Output saved to: {output_file}")

            # Print stdout output
            print("\n" + "="*80)
            print("COMMAND OUTPUT (stdout):")
            print("="*80)
            if stdout_text:
                print(stdout_text)
            else:
                print("No stdout output")
            
            # Print stderr if exists
            if stderr_text:
                print("\n" + "="*80)
                print("ERROR OUTPUT (stderr):")
                print("="*80)
                print(stderr_text)
            
            return {
                'success': returncode == 0,
                'returncode': returncode,
                'target': target,
                'output_file': output_file,
                'stdout': stdout_text,
                'stderr': stderr_text,
                'matches_found': len(stdout_text.strip().split('\n')) if stdout_text else 0
            }
            
        except Exception as e:
            print(f"[-] Error executing command: {e}")
            return {
                'success': False,
                'error': str(e),
                'target': target
            }

async def test_plugin():
    """
    Simple test function to verify the plugin works
    """
    print("=== Testing ScrapingGitHub Plugin ===")
    
    # Create plugin instance
    plugin = NewPlugin()
    
    # Test parameters
    target = 'baneco.com.bo'
    output = os.getcwd()
    
    print(f"Plugin Name: {plugin.name}")
    print(f"Description: {plugin.description}")
    print(f"Target: {target}")
    print(f"Output Directory: {output}")
    print("-" * 50)
    
    # Run the plugin
    result = await plugin.run(target=target, output=output)
    
    print("\n=== Test Results ===")
    print(f"Success: {result['success']}")
    print(f"Return Code: {result['returncode']}")
    print(f"Output File: {result.get('output_file', 'N/A')}")
    print(f"Matches Found: {result.get('matches_found', 0)}")
    
    if result['stderr']:
        print(f"Errors: {result['stderr']}")
    
    return result

if __name__ == '__main__':
    # Test the plugin
    asyncio.run(test_plugin())
