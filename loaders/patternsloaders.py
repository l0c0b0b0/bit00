import importlib.util
from pathlib import Path
#from helpers.io import error

class PatternsLoader:
    def __init__(self, module: str):
        repo_root = Path(__file__).resolve().parent.parent
        m_patterns = repo_root / 'modules' / module / 'patterns.py'
        self.patterns_file = m_patterns
        self.patterns = self.load_patterns()

    def load_patterns(self):
        if not self.patterns_file.exists():
            raise FileNotFoundError(f"Patterns file not found: {self.patterns_file}")
        
        # Import the module dynamically
        spec = importlib.util.spec_from_file_location("patterns_module", self.patterns_file)
        patterns_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(patterns_module)
        
        return getattr(patterns_module, "PATTERNS", {})
       
    
    def get_patterns_by_mode(self, mode: str):
        return self.patterns.get(mode, {})
    
    def get_patterns_by_name(self, mode, name: str):
        for mode, tools in self.patterns.items():
            if name in tools.keys():
                return self.patterns[mode][name]

        return self.patterns[mode]["GlobalPatterns"]
