import os
import yaml
import sys
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

console = Console()

# Minimalist 2-Color Palette (Blue & Black)
ACCENT = "blue"
TEXT = "black"
PROMPT = f"bold {TEXT}"

class GliardInterface:
    def __init__(self, root_dir: str):
        self.root_dir = root_dir
        self.config_path = os.path.join(root_dir, "config.yaml")
        self.config = self._load_config()
        
        # Dashboard State
        self.recent_projects = self.config.get("recent_projects", [])
        self.target_dir = self.recent_projects[0] if self.recent_projects else "."
        self.tier = self.config.get("edition", "guard").lower()
        self.report_name = "gliard_report"
        self.report_dir = self.config.get("report_dir", "reports")

    def _load_config(self):
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f) or {}
        return {"edition": "guard", "scanners": {}}

    def _save_config(self):
        with open(self.config_path, 'w') as f:
            yaml.dump(self.config, f)

    def display_main_menu(self):
        while True:
            console.clear()
            
            # Full Block ASCII Logo in ACCENT color (Left aligned)
            ascii_logo = (
                f"[bold {ACCENT}]"
                " ██████      ██          ██      █████      ██████      ██████  \n"
                "██           ██          ██     ██   ██     ██   ██     ██   ██ \n"
                "██   ███     ██          ██     ███████     ██████      ██   ██ \n"
                "██    ██     ██          ██     ██   ██     ██   ██     ██   ██ \n"
                " ██████      ███████     ██     ██   ██     ██   ██     ██████  \n"
                f"[bold {TEXT}]A G E N T   A U D I T   S C A N[/bold {TEXT}]"
                f"[/bold {ACCENT}]"
            )
            
            console.print("\n")
            console.print(ascii_logo)
            console.print("\n") # Spacing before menu

            # Display Status Table (Settings 1-4)
            status_table = Table(show_header=False, box=None, padding=(0, 1))
            status_table.add_column("Option", style=f"bold {ACCENT}", width=5)
            status_table.add_column("Parameter", style=TEXT, width=22)
            status_table.add_column("Current Value", style=ACCENT)

            status_table.add_row("[1]", "Agent Directory", f"[bold]{self.target_dir}[/bold]")
            status_table.add_row("[2]", "Audit Tier", f"[bold]{self.tier.upper()}[/bold]")
            status_table.add_row("[3]", "Report Settings", f"[{TEXT}]{self.report_name}[/{TEXT}]")
            status_table.add_row("[4]", "General Settings", f"[{TEXT}](Exclusions, History)[/{TEXT}]")

            console.print(status_table)
            
            # Action Area
            console.print("\n")
            console.print(f" [[bold {ACCENT}]S[/bold {ACCENT}]] [bold]START AGENT AUDIT[/bold]")
            console.print("\n")
            console.print(f" [[bold {ACCENT}]E[/bold {ACCENT}]] EXIT")
            console.print("\n")

            choice = Prompt.ask(
                f"[{PROMPT}]Select an option (1-4, S, E)[/{PROMPT}]", 
                choices=["1", "2", "3", "4", "S", "s", "E", "e"], 
                show_choices=False
            ).upper()

            if choice == "1":
                self._set_target()
            elif choice == "2":
                self._set_tier()
            elif choice == "3":
                self.display_report_settings_menu()
            elif choice == "4":
                self.display_settings_menu()
            elif choice == "S":
                self._run_scan()
            elif choice == "E":
                console.print(f"[{TEXT}]Goodbye![/{TEXT}]")
                break

    def display_report_settings_menu(self):
        while True:
            console.clear()
            console.print(Panel(f"[bold {ACCENT}]REPORT SETTINGS[/bold {ACCENT}]", border_style=ACCENT))
            
            table = Table(show_header=False, box=None, padding=(0, 1))
            table.add_column("Option", style=f"bold {ACCENT}", width=5)
            table.add_column("Parameter", style=TEXT, width=22)
            table.add_column("Value", style=ACCENT)
            
            table.add_row("[1]", "Report Name", self.report_name)
            table.add_row("[2]", "Output Directory", self.report_dir)
            table.add_row("[3]", "Back to Dashboard", "")
            
            console.print(table)
            
            choice = Prompt.ask(f"[{PROMPT}]Select an option (1-3)[/{PROMPT}]", choices=["1", "2", "3"], show_choices=False)
            
            if choice == "1":
                self.report_name = Prompt.ask(f"[{PROMPT}]Enter report name[/{PROMPT}]", default=self.report_name)
            elif choice == "2":
                self.report_dir = Prompt.ask(f"[{PROMPT}]Enter output directory[/{PROMPT}]", default=self.report_dir)
                self.config["report_dir"] = self.report_dir
                self._save_config()
            elif choice == "3":
                break

    def _set_target(self):
        if self.recent_projects:
            console.print(f"\n[bold {ACCENT}]Recent Projects:[/bold {ACCENT}]")
            for i, p in enumerate(self.recent_projects[:5]):
                console.print(f" [{ACCENT}]{i+1}.[/{ACCENT}] {p}")
            
            p_choice = Prompt.ask(f"\n[{PROMPT}]Select a project (1-5) or enter new path[/{PROMPT}]", default="1", show_choices=False)
            if p_choice.isdigit() and 1 <= int(p_choice) <= len(self.recent_projects):
                self.target_dir = self.recent_projects[int(p_choice)-1]
                return

        new_target = Prompt.ask(f"\n[{PROMPT}]Enter Agent Directory[/{PROMPT}]", default=self.target_dir)
        if os.path.exists(new_target):
            self.target_dir = os.path.abspath(new_target)
            self._add_recent_project(self.target_dir)
        else:
            console.print(f"[{ACCENT}]Error: Path '{new_target}' does not exist.[/{ACCENT}]")
            Prompt.ask(f"[{TEXT}]Press Enter[/{TEXT}]")

    def _add_recent_project(self, path: str):
        if path in self.recent_projects:
            self.recent_projects.remove(path)
        self.recent_projects.insert(0, path)
        self.recent_projects = self.recent_projects[:10]
        self.config["recent_projects"] = self.recent_projects
        self._save_config()

    def _set_tier(self):
        while True:
            console.clear()
            console.print(Panel(f"[bold {ACCENT}]AUDIT TIER SELECTION[/bold {ACCENT}]", border_style=ACCENT))
            
            table = Table(show_header=False, box=None, padding=(0, 1))
            table.add_column("Option", style=f"bold {ACCENT}", width=5)
            table.add_column("Tier", style=TEXT, width=22)
            table.add_column("Description", style=TEXT)
            
            table.add_row("[1]", "GUARD", "Compliance & Security Focus")
            table.add_row("[2]", "SENTINEL", "Adversary Simulation (Advanced)")
            table.add_row("[3]", "CORE", "Basic Security Hygiene")
            table.add_row("[4]", "Back to Dashboard", "")
            
            console.print(table)
            
            t_choice = Prompt.ask(f"[{PROMPT}]Select tier (1-4)[/{PROMPT}]", choices=["1", "2", "3", "4"], default="1", show_choices=False)
            
            if t_choice == "4":
                break
            
            t_map = {"1": "guard", "2": "sentinel", "3": "core"}
            if t_choice in t_map:
                self.tier = t_map[t_choice]
                self.config["edition"] = self.tier
                self._save_config()
            break

    def _run_scan(self):
        original_edition = self.config.get("edition", "guard")
        self.config["edition"] = self.tier
        self._save_config()
        
        abs_target = os.path.abspath(self.target_dir)
        self._add_recent_project(abs_target)

        # Handle output directory
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir, exist_ok=True)
            
        full_output_path = os.path.join(self.report_dir, self.report_name)

        console.print(f"\n[bold {ACCENT}]Initializing {self.tier.upper()} Audit...[/bold {ACCENT}]\n")
        subprocess.run([sys.executable, os.path.join(self.root_dir, "main.py"), abs_target, "--output", full_output_path])
        
        self.config["edition"] = original_edition
        self._save_config()
        Prompt.ask(f"\n[bold {ACCENT}]Audit Complete.[/bold {ACCENT}] [{TEXT}]Press Enter[/{TEXT}]")

    def display_settings_menu(self):
        while True:
            console.clear()
            console.print(Panel(f"[bold {ACCENT}]GENERAL SETTINGS[/bold {ACCENT}]", border_style=ACCENT))
            
            table = Table(show_header=False, box=None, padding=(0, 1))
            table.add_column("Option", style=f"bold {ACCENT}", width=5)
            table.add_column("Parameter", style=TEXT, width=22)
            table.add_column("Info", style=TEXT)
            
            table.add_row("[1]", "Manage Exclusions", f"[{TEXT}]({len(self.config.get('exclude_dirs', []))} dirs ignored)[/{TEXT}]")
            table.add_row("[2]", "Clear Project History", f"[{TEXT}](Recent paths)[/{TEXT}]")
            table.add_row("[3]", "Back to Dashboard")
            
            console.print(table)
            
            choice = Prompt.ask(f"[{PROMPT}]Select an option (1-3)[/{PROMPT}]", choices=["1", "2", "3"], show_choices=False)
            
            if choice == "1":
                self._manage_exclusions()
            elif choice == "2":
                self.recent_projects = []
                self.config["recent_projects"] = []
                self._save_config()
                console.print(f"[{ACCENT}]History cleared.[/{ACCENT}]")
                Prompt.ask(f"[{TEXT}]Press Enter[/{TEXT}]")
            elif choice == "3":
                break

    def _manage_exclusions(self):
        current = self.config.get("exclude_dirs", [])
        console.print(f"\n[bold {ACCENT}]Current exclusions:[/bold {ACCENT}] {', '.join(current) if current else 'None'}")
        new_dir = Prompt.ask(f"[{PROMPT}]Add directory to exclude[/{PROMPT}]")
        
        if not new_dir:
            self.config["exclude_dirs"] = []
        else:
            if "exclude_dirs" not in self.config: self.config["exclude_dirs"] = []
            if new_dir not in self.config["exclude_dirs"]:
                self.config["exclude_dirs"].append(new_dir)
        
        self._save_config()
        console.print(f"[{ACCENT}]Settings saved.[/{ACCENT}]")
        Prompt.ask(f"[{TEXT}]Press Enter[/{TEXT}]")
