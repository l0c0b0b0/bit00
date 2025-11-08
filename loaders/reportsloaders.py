import os
import sys
import importlib.util
from pathlib import Path
import glob
from helpers.io import info, error, warn, debug

class ReportsLoader:
    def __init__(self, module_name):
        self.module_name = module_name
        # Use current working directory (where user runs bit00.py) for logs
        self.current_dir = os.getcwd()
        # Get the project root directory for modules
        self.root_dir = self.find_project_root()
        self.modules_dir = os.path.join(self.root_dir, "modules")
        self.reports_dir = os.path.join(self.current_dir, "reports")  # Save reports in current dir
        self.patterns_logs = []

    def find_project_root(self):
        """Find the project root directory containing bit00.py"""
        # Start from the directory of this file
        current_file = os.path.abspath(__file__)
        current_dir = os.path.dirname(current_file)
        
        # Look for bit00.py in parent directories
        check_dir = current_dir
        for _ in range(10):  # Limit search depth
            if os.path.exists(os.path.join(check_dir, "bit00.py")):
                return check_dir
            parent = os.path.dirname(check_dir)
            if parent == check_dir:  # Reached filesystem root
                break
            check_dir = parent
        
        # Fallback: use the parent of the loaders directory
        return os.path.dirname(current_dir)

    def discover_patterns_logs(self):
        """Discover all patterns.log files for the given module"""
        info(f"Current working directory: {self.current_dir}")
        #info(f"Project root directory: {self.root_dir}")
        
        # Look for logs in CURRENT WORKING DIRECTORY (where user runs the program)
        if self.module_name == "osint":
            search_pattern = os.path.join(self.current_dir, "osint", "*", "logs", "patterns.log")
        else:  # netscan
            search_pattern = os.path.join(self.current_dir, "recon", "*", "logs", "patterns.log")
        
        info(f"Searching for logs with pattern: {search_pattern}")
        
        self.patterns_logs = glob.glob(search_pattern)
        
        # Debug: Check if the base directories exist
        if self.module_name == "osint":
            base_dir = os.path.join(self.current_dir, "osint")
        else:
            base_dir = os.path.join(self.current_dir, "recon")
            
        if os.path.exists(base_dir):
            debug(f"✓ Base directory exists: {base_dir}")
            # List targets in the base directory
            targets = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
            debug(f"  Found targets: {targets}")
            
            # Check each target for logs
            for target in targets:
                logs_dir = os.path.join(base_dir, target, "logs")
                patterns_file = os.path.join(logs_dir, "patterns.log")
                if os.path.exists(patterns_file):
                    debug(f"  ✓ Found patterns.log for {target}: {patterns_file}")
                else:
                    debug(f"  ✗ No patterns.log for {target} (logs dir exists: {os.path.exists(logs_dir)})")
        else:
            error(f"✗ Base directory not found: {base_dir}")
            error(f"  Current directory contents: {os.listdir(self.current_dir)}")
        
        debug(f"Found {len(self.patterns_logs)} patterns.log files for {self.module_name}:")
        for log in self.patterns_logs:
            debug(f"  - {log}")
        
        return self.patterns_logs

    def discover_patterns_logs_from_dir(self, search_dir):
        """Discover all patterns.log files from a specific directory"""
        debug(f"Searching for patterns.log files in: {search_dir}")
        
        # Look for patterns.log files recursively in the given directory
        search_pattern = os.path.join(search_dir, "**", "patterns.log")
        self.patterns_logs = glob.glob(search_pattern, recursive=True)
        
        debug(f"Found {len(self.patterns_logs)} patterns.log files in {search_dir}:")
        for log in self.patterns_logs:
            debug(f"  - {log}")
        
        return self.patterns_logs

    def load_module_report(self):
        """Load and execute the report.py for the specific module"""
        module_path = os.path.join(self.modules_dir, self.module_name, "report.py")
        
        debug(f"Looking for module at: {module_path}")
        
        if not os.path.exists(module_path):
            error(f"Report module not found: {module_path}")
            return False
        
        debug(f"Found report module at: {module_path}")
        
        try:
            # Dynamically import the module
            spec = importlib.util.spec_from_file_location(f"{self.module_name}.report", module_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[f"{self.module_name}.report"] = module
            spec.loader.exec_module(module)
            
            # Check if the module has the required function
            if hasattr(module, 'generate_reports'):
                # Create reports directory if it doesn't exist
                os.makedirs(self.reports_dir, exist_ok=True)
                
                # Pass all discovered patterns logs to the module
                module.generate_reports(self.patterns_logs, self.reports_dir)
                info("Successfully generated reports for {bgreen}{self.module_name}{rst}")
                return True
            else:
                error(f"✗ Module {self.module_name} doesn't have generate_reports function")
                return False
                
        except Exception as e:
            error(f"✗ Error loading module {self.module_name}: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

    def generate_reports(self):
        """Generate reports for the specific module"""
        mu=self.module_name.upper()
        info("{bgreen}{mysc}{rst}", mysc='='*50)
        info("Generating reports for:{bgreen}{mu}{rst}")
        info("{bgreen}{mysc}{rst}", mysc='='*50)
        
        # First discover all patterns.log files
        logs_found = self.discover_patterns_logs()
        
        if not logs_found:
            error(f"✗ No patterns.log files found for {self.module_name}")
            error(f"Please make sure you have run scans first.")
            error(f"Expected location: {self.current_dir}/{self.module_name}/*/logs/patterns.log")
            return False
        
        # Then load and execute the module's report generator
        success = self.load_module_report()
        
        if success:
            info("✓ Completed {bgreen}{mu}{rst} report generation")
            info("Reports saved to: {bblue}{_dir}/{rst}", _dir=self.reports_dir)
        else:
            error(f"✗ Failed to generate {self.module_name.upper()} reports")
            
        return success

    def generate_reports_from_dir(self, search_dir, output_dir=None):
        """Generate reports using patterns.log files from a specific directory
        
        Args:
            search_dir (str): Directory to search for patterns.log files
            output_dir (str, optional): Directory to save reports. If None, uses default reports directory
        """
        mu=self.module_name.upper()
        ddir = search_dir
        info("{bgreen}{mysc}{rst}", mysc='='*50)
        info("Generating {bgreen}{mu}{rst} reports from directory: {bgreen}{ddir}{rst}")
        info("{bgreen}{mysc}{rst}", mysc='='*50)
        
        # Validate the search directory
        if not os.path.exists(search_dir):
            error(f"✗ Search directory not found: {search_dir}")
            return False
        
        # Set custom output directory if provided
        if output_dir:
            self.reports_dir = output_dir
            #debug(f"Using custom output directory: {output_dir}")
        
        # Discover patterns.log files from the specified directory
        logs_found = self.discover_patterns_logs_from_dir(search_dir)
        
        if not logs_found:
            error(f"✗ No patterns.log files found in: {search_dir}")
            return False
        
        # Load and execute the module's report generator
        success = self.load_module_report()
        
        if success:
            info("Completed {bgreen}{mu}{rst} report generation")
            info("Reports saved to: {bblue}{re_dir}{rst}/", re_dir=self.reports_dir)
        else:
            error(f"✗ Failed to generate {self.module_name.upper()} reports")
            
        return success