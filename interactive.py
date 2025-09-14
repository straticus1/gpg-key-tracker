#!/usr/bin/env python3
"""
Interactive mode for GPG Key Tracker
"""

import click
import os
import sys
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typing import Optional, Dict, Any

from gpg_manager import GPGManager
from config import get_config
from monitoring import get_health_checker, get_metrics_collector
from backup_manager import BackupManager

console = Console()


class InteractiveMode:
    """Interactive mode for GPG Key Tracker"""

    def __init__(self):
        """Initialize interactive mode"""
        self.config = get_config()
        self.gpg_manager = GPGManager(config=self.config)
        self.health_checker = get_health_checker()
        self.metrics_collector = get_metrics_collector()
        self.backup_manager = BackupManager(config=self.config)

    def main_menu(self):
        """Display main menu"""
        console.clear()
        console.print(Panel.fit(
            "[bold blue]GPG Key Tracker - Interactive Mode[/bold blue]\n"
            f"Version: 1.2.0\n"
            f"Database: {self.config.database.path}\n"
            f"GPG Home: {self.config.gpg.home}",
            title="Welcome"
        ))

        while True:
            try:
                choice = Prompt.ask(
                    "\n[bold cyan]Main Menu[/bold cyan]\n\n"
                    "1. Key Management\n"
                    "2. Usage Logs\n"
                    "3. Reports\n"
                    "4. Backup & Restore\n"
                    "5. System Status\n"
                    "6. Configuration\n"
                    "7. Help\n"
                    "0. Exit\n\n"
                    "Choose an option",
                    choices=["0", "1", "2", "3", "4", "5", "6", "7"],
                    default="1"
                )

                if choice == "0":
                    if Confirm.ask("Are you sure you want to exit?"):
                        console.print("[green]Goodbye![/green]")
                        break
                elif choice == "1":
                    self.key_management_menu()
                elif choice == "2":
                    self.usage_logs_menu()
                elif choice == "3":
                    self.reports_menu()
                elif choice == "4":
                    self.backup_menu()
                elif choice == "5":
                    self.system_status_menu()
                elif choice == "6":
                    self.configuration_menu()
                elif choice == "7":
                    self.show_help()

            except KeyboardInterrupt:
                console.print("\n[yellow]Use '0' to exit gracefully[/yellow]")
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
                input("Press Enter to continue...")

    def key_management_menu(self):
        """Key management submenu"""
        while True:
            choice = Prompt.ask(
                "\n[bold cyan]Key Management[/bold cyan]\n\n"
                "1. List Keys\n"
                "2. Add New Key\n"
                "3. View Key Details\n"
                "4. Edit Key Metadata\n"
                "5. Activate/Deactivate Key\n"
                "6. Delete Key\n"
                "7. Check Expiring Keys\n"
                "8. Check Expired Keys\n"
                "9. Update Key Expiry Status\n"
                "0. Back to Main Menu\n\n"
                "Choose an option",
                choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
                default="1"
            )

            if choice == "0":
                break
            elif choice == "1":
                self.list_keys()
            elif choice == "2":
                self.add_key()
            elif choice == "3":
                self.view_key_details()
            elif choice == "4":
                self.edit_key()
            elif choice == "5":
                self.toggle_key_status()
            elif choice == "6":
                self.delete_key()
            elif choice == "7":
                self.check_expiring_keys()
            elif choice == "8":
                self.check_expired_keys()
            elif choice == "9":
                self.update_expiry_status()

    def list_keys(self):
        """List GPG keys"""
        include_inactive = Confirm.ask("Include inactive keys?", default=False)

        try:
            keys = self.gpg_manager.list_keys(include_inactive=include_inactive)

            if not keys:
                console.print(Panel.fit("No keys found", title="No Keys"))
                input("Press Enter to continue...")
                return

            table = Table(title=f"GPG Keys ({'All' if include_inactive else 'Active Only'})")
            table.add_column("Status", style="bold")
            table.add_column("Fingerprint", style="cyan")
            table.add_column("Owner", style="green")
            table.add_column("Email", style="yellow")
            table.add_column("Created", style="dim")
            table.add_column("Expires", style="red")

            for key in keys:
                status = "[green]✓[/green]" if key['is_active'] else "[red]✗[/red]"
                expires = key['expires_at'].strftime('%Y-%m-%d') if key['expires_at'] else 'Never'
                if key['is_expired']:
                    expires = f"[bold red]{expires}[/bold red]"

                table.add_row(
                    status,
                    key['fingerprint'][:16] + "...",
                    key['owner'],
                    key['email'] or 'N/A',
                    key['created_at'].strftime('%Y-%m-%d'),
                    expires
                )

            console.print(table)
            input("Press Enter to continue...")

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            input("Press Enter to continue...")

    def add_key(self):
        """Add new GPG key"""
        try:
            console.print("\n[bold cyan]Add New GPG Key[/bold cyan]\n")

            key_file = Prompt.ask("Path to GPG key file (.asc)")
            if not os.path.exists(key_file):
                console.print("[red]File does not exist[/red]")
                input("Press Enter to continue...")
                return

            owner = Prompt.ask("Key owner name")
            requester = Prompt.ask("Requester name")
            jira_ticket = Prompt.ask("JIRA ticket (optional)", default="")
            notes = Prompt.ask("Notes (optional)", default="")

            console.print("\n[yellow]Adding key...[/yellow]")

            result = self.gpg_manager.add_key(
                key_file=key_file,
                owner=owner,
                requester=requester,
                jira_ticket=jira_ticket or None,
                notes=notes or None
            )

            if result:
                console.print(Panel.fit(
                    f"[green]✓[/green] Key added successfully!\n"
                    f"Owner: {owner}\n"
                    f"Requester: {requester}",
                    title="Success"
                ))
            else:
                console.print(Panel.fit(
                    "[red]✗[/red] Failed to add key",
                    title="Error"
                ))

            input("Press Enter to continue...")

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            input("Press Enter to continue...")

    def view_key_details(self):
        """View detailed key information"""
        try:
            fingerprint = Prompt.ask("Enter key fingerprint (partial match accepted)")

            # Find matching keys
            keys = self.gpg_manager.list_keys(include_inactive=True)
            matches = [k for k in keys if fingerprint.lower() in k['fingerprint'].lower()]

            if not matches:
                console.print("[red]No matching keys found[/red]")
                input("Press Enter to continue...")
                return

            if len(matches) > 1:
                console.print("\n[yellow]Multiple matches found:[/yellow]")
                for i, key in enumerate(matches):
                    console.print(f"{i+1}. {key['fingerprint'][:16]}... ({key['owner']})")

                choice = Prompt.ask("Select key", choices=[str(i+1) for i in range(len(matches))])
                selected_key = matches[int(choice)-1]
            else:
                selected_key = matches[0]

            # Get full key details
            key_info = self.gpg_manager.get_key_by_fingerprint(selected_key['fingerprint'])

            if key_info:
                info_text = f"""
[bold]Key Information[/bold]

[bright_blue]Fingerprint:[/bright_blue] {key_info['fingerprint']}
[bright_blue]Key ID:[/bright_blue] {key_info['key_id']}
[bright_blue]User ID:[/bright_blue] {key_info['user_id']}
[bright_blue]Name:[/bright_blue] {key_info['name'] or 'N/A'}
[bright_blue]Email:[/bright_blue] {key_info['email'] or 'N/A'}

[bright_green]Owner:[/bright_green] {key_info['owner']}
[bright_green]Requester:[/bright_green] {key_info['requester']}
[bright_green]JIRA Ticket:[/bright_green] {key_info['jira_ticket'] or 'N/A'}

[bright_yellow]Created:[/bright_yellow] {key_info['created_at'].strftime('%Y-%m-%d %H:%M:%S')}
[bright_yellow]Updated:[/bright_yellow] {key_info['updated_at'].strftime('%Y-%m-%d %H:%M:%S')}
[bright_yellow]Expires:[/bright_yellow] {key_info['expires_at'].strftime('%Y-%m-%d') if key_info['expires_at'] else 'Never'}
[bright_yellow]Last Used:[/bright_yellow] {key_info['last_used_at'].strftime('%Y-%m-%d %H:%M:%S') if key_info['last_used_at'] else 'Never'}
[bright_yellow]Usage Count:[/bright_yellow] {key_info['usage_count'] or 0}

[bright_magenta]Status:[/bright_magenta] {'Active' if key_info['is_active'] else 'Inactive'}
[bright_magenta]Expired:[/bright_magenta] {'Yes' if key_info['is_expired'] else 'No'}

[bright_cyan]Notes:[/bright_cyan]
{key_info['notes'] or 'No notes'}
                """

                console.print(Panel(info_text, title="Key Details"))

            input("Press Enter to continue...")

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            input("Press Enter to continue...")

    def edit_key(self):
        """Edit key metadata"""
        # Implementation similar to view_key_details but with edit prompts
        console.print("[yellow]Edit Key - Not implemented in interactive mode yet[/yellow]")
        console.print("Use: gpg-tracker edit-key --fingerprint <fingerprint> --owner <new_owner>")
        input("Press Enter to continue...")

    def toggle_key_status(self):
        """Toggle key active/inactive status"""
        console.print("[yellow]Toggle Key Status - Not implemented in interactive mode yet[/yellow]")
        console.print("Use: gpg-tracker activate-key/deactivate-key --fingerprint <fingerprint>")
        input("Press Enter to continue...")

    def delete_key(self):
        """Delete a key"""
        console.print("[yellow]Delete Key - Not implemented in interactive mode yet[/yellow]")
        console.print("Use: gpg-tracker delete-key --fingerprint <fingerprint>")
        input("Press Enter to continue...")

    def check_expiring_keys(self):
        """Check expiring keys"""
        try:
            days = Prompt.ask("Days ahead to check", default="30")
            expiring_keys = self.gpg_manager.get_expiring_keys(int(days))

            if not expiring_keys:
                console.print(Panel.fit(f"No keys expiring within {days} days", title="No Expiring Keys"))
            else:
                table = Table(title=f"Keys Expiring Within {days} Days")
                table.add_column("Fingerprint", style="cyan")
                table.add_column("Owner", style="green")
                table.add_column("Expires", style="red")
                table.add_column("Days Left", style="bold red")

                for key in expiring_keys:
                    table.add_row(
                        key['fingerprint'][:16] + "...",
                        key['owner'],
                        key['expires_at'].strftime('%Y-%m-%d'),
                        str(key['days_until_expiry'])
                    )

                console.print(table)

            input("Press Enter to continue...")

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            input("Press Enter to continue...")

    def check_expired_keys(self):
        """Check expired keys"""
        try:
            expired_keys = self.gpg_manager.get_expired_keys()

            if not expired_keys:
                console.print(Panel.fit("No expired keys found", title="No Expired Keys"))
            else:
                table = Table(title="Expired Keys")
                table.add_column("Fingerprint", style="cyan")
                table.add_column("Owner", style="green")
                table.add_column("Expired", style="red")
                table.add_column("Days Ago", style="bold red")

                for key in expired_keys:
                    table.add_row(
                        key['fingerprint'][:16] + "...",
                        key['owner'],
                        key['expires_at'].strftime('%Y-%m-%d'),
                        str(key['days_since_expiry'])
                    )

                console.print(table)

            input("Press Enter to continue...")

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            input("Press Enter to continue...")

    def update_expiry_status(self):
        """Update key expiry status"""
        try:
            console.print("[yellow]Updating expiry status...[/yellow]")
            refreshed = self.gpg_manager.refresh_key_expiry_dates()
            updated = self.gpg_manager.update_key_expiry_status()

            console.print(Panel.fit(
                f"[green]✓[/green] Update completed!\n"
                f"Keys refreshed: {refreshed}\n"
                f"Keys updated: {updated}",
                title="Update Complete"
            ))

            input("Press Enter to continue...")

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            input("Press Enter to continue...")

    def usage_logs_menu(self):
        """Usage logs submenu"""
        console.print("[yellow]Usage Logs - Basic view only in interactive mode[/yellow]")
        console.print("Use CLI commands for full functionality:")
        console.print("- gpg-tracker logs")
        console.print("- gpg-tracker logs --fingerprint <fingerprint>")
        input("Press Enter to continue...")

    def reports_menu(self):
        """Reports submenu"""
        console.print("[yellow]Reports - Use CLI commands for full functionality:[/yellow]")
        console.print("- gpg-tracker generate-report --format html")
        console.print("- gpg-tracker generate-report --days 30 --format csv")
        console.print("- gpg-tracker auto-report --format html --recipients email@domain.com")
        input("Press Enter to continue...")

    def backup_menu(self):
        """Backup & restore submenu"""
        console.print("[yellow]Backup & Restore - Use CLI commands for full functionality:[/yellow]")
        console.print("- gpg-tracker create-backup")
        console.print("- gpg-tracker list-backups")
        console.print("- gpg-tracker restore-backup --backup-name <name>")
        input("Press Enter to continue...")

    def system_status_menu(self):
        """System status submenu"""
        try:
            health_status = self.health_checker.get_overall_health()
            metrics = self.metrics_collector.get_current_metrics()

            # Display health status
            status_color = "green" if health_status['status'] == 'healthy' else "yellow" if health_status['status'] == 'degraded' else "red"

            console.print(Panel.fit(
                f"[{status_color}]{health_status['status'].upper()}[/{status_color}]\n"
                f"Timestamp: {health_status['timestamp']}\n\n"
                f"[bright_blue]Keys:[/bright_blue] {metrics.total_keys} total, {metrics.active_keys} active\n"
                f"[bright_green]Operations:[/bright_green] {metrics.total_operations} total, {metrics.success_rate:.1f}% success\n"
                f"[bright_yellow]Database:[/bright_yellow] {metrics.database_size_mb:.1f}MB" if metrics.database_size_mb else "",
                title="System Status"
            ))

            input("Press Enter to continue...")

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            input("Press Enter to continue...")

    def configuration_menu(self):
        """Configuration submenu"""
        console.print("[yellow]Current Configuration:[/yellow]")
        console.print(f"Database: {self.config.database.path}")
        console.print(f"GPG Home: {self.config.gpg.home}")
        console.print(f"Log Level: {self.config.logging.level}")
        console.print(f"Backup Enabled: {self.config.backup.enabled}")
        console.print(f"Monitoring Enabled: {self.config.monitoring.enabled}")
        console.print("\nUse environment variables or config files to modify settings.")
        input("Press Enter to continue...")

    def show_help(self):
        """Show help information"""
        help_text = """
[bold cyan]GPG Key Tracker - Interactive Mode Help[/bold cyan]

[bold]Navigation:[/bold]
- Use number keys to select menu options
- Press Ctrl+C to interrupt operations
- Use '0' to go back or exit

[bold]Key Management:[/bold]
- List, add, view, edit, and delete GPG keys
- Check expiring and expired keys
- Manage key activation status

[bold]CLI Commands:[/bold]
For advanced operations, use the CLI:
- gpg-tracker --help
- gpg-tracker add-key --help
- gpg-tracker generate-report --help

[bold]Aliases:[/bold]
- ls = list-keys
- add = add-key
- rm = delete-key
- log = logs
- status = health-check
- stats = metrics

[bold]Documentation:[/bold]
Visit: https://straticus1.github.io/gpg-key-tracker/
        """

        console.print(Panel(help_text, title="Help"))
        input("Press Enter to continue...")


def start_interactive_mode():
    """Start interactive mode"""
    try:
        interactive = InteractiveMode()
        interactive.main_menu()
    except KeyboardInterrupt:
        console.print("\n[yellow]Exiting interactive mode...[/yellow]")
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)


if __name__ == '__main__':
    start_interactive_mode()