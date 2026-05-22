from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Dict, Type

class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class Finding:
    category: str
    title: str
    description: str
    severity: Severity
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    snippet: Optional[str] = None
    recommendation: Optional[str] = None
    owasp_id: Optional[str] = None
    owasp_category: Optional[str] = None
    locations: Optional[List[str]] = None

    @property
    def score(self) -> int:
        scores = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 10,
            Severity.LOW: 5,
            Severity.INFO: 0
        }
        return scores.get(self.severity, 0)

class Edition(Enum):
    CORE = 1
    GUARD = 2
    SENTINEL = 3

    @classmethod
    def from_str(cls, val: str):
        val = val.lower()
        if val == "sentinel": return cls.SENTINEL
        if val == "guard": return cls.GUARD
        if val == "core": return cls.CORE
        
        # Warning for typos
        print(f" [bold yellow]⚠[/bold yellow] [yellow]Warning: Unknown edition '{val}' in config. Fallback to CORE.[/yellow]")
        return cls.CORE

class Scanner:
    # Default tier for scanners is GUARD. 
    # Core scanners will override this.
    min_edition: Edition = Edition.GUARD

    def __init__(self, root_dir: str, config: dict = None):
        self.root_dir = root_dir
        self.config = config or {}
        # Dynamic exclusions from config
        self.exclude_dirs = set(self.config.get('exclude_dirs', [
            'node_modules', '.git', '__pycache__', 'venv', '.env', 'dist', 'build',
            '.next', '.gemini', 'site-packages', 'bin', 'obj', '.venv', 'env',
            'web/node_modules', 'web/dist', '.tox', 'htmlcov', '.mypy_cache',
            '.pytest_cache', 'eggs', '*.egg-info'
        ]))
        self.exclude_files = set(self.config.get('exclude_files', [
            'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'composer.lock'
        ]))
        self.exclude_extensions = set(self.config.get('exclude_extensions', [
            '.map', '.min.js', '.min.css', '.ico', '.png', '.jpg', '.jpeg', '.svg', '.woff', '.woff2'
        ]))

    def _should_exclude_dir(self, dirname: str, dirpath: str) -> bool:
        """Check if directory should be excluded based on name or path patterns."""
        if dirname in self.exclude_dirs:
            return True
        # Exclude common build/dependency patterns regardless of nesting
        _ALWAYS_EXCLUDE = {
            'node_modules', '.venv', 'venv', 'env', '__pycache__',
            'dist', 'build', '.git', 'site-packages', '.next',
            '.tox', '.mypy_cache', '.pytest_cache', 'htmlcov'
        }
        return dirname in _ALWAYS_EXCLUDE

    def get_scanner_config(self) -> dict:
        """Helper to get settings for this specific scanner from the global config."""
        scanner_name = self.__class__.__name__
        return self.config.get('scanners', {}).get(scanner_name, {})

    def scan(self) -> List[Finding]:
        raise NotImplementedError("Subclasses must implement scan()")

class ScannerRegistry:
    _scanners: Dict[str, Type[Scanner]] = {}

    @classmethod
    def register(cls, name: str):
        def wrapper(scanner_class):
            cls._scanners[name] = scanner_class
            return scanner_class
        return wrapper

    @classmethod
    def get_scanners(cls, config: dict, root_dir: str) -> List[Scanner]:
        active_scanners = []
        scanner_configs = config.get('scanners', {})
        current_edition = Edition.from_str(config.get('edition', 'core'))
        
        for name, scanner_class in cls._scanners.items():
            # Filter by edition
            if scanner_class.min_edition.value > current_edition.value:
                continue
                
            scanner_config = scanner_configs.get(name, {})
            # Default to True if not specified in config
            if scanner_config.get('enabled', True):
                active_scanners.append(scanner_class(root_dir, config=config))
        
        return active_scanners
