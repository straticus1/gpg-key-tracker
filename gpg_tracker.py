#!/usr/bin/env python3
"""
GPG Key Tracker - Main CLI application
"""

import click
import os
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from datetime import datetime
from dotenv import load_dotenv

# Add lib directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from lib.gpg_manager import GPGManager
from lib.models import create_database
from lib.report_generator import ReportGenerator, ReportExporter
from lib.backup_manager import BackupManager
from lib.config import get_config
from lib.monitoring import get_metrics_collector, get_health_checker
from lib.interactive import start_interactive_mode

load_dotenv()

console = Console()

@click.group()
@click.version_option(version='1.2.0')
def cli():
    """GPG Key Tracker - Manage and track GPG keys with metadata"""
    pass

@cli.command()
def init():
    """Initialize the database"""
    try:
        create_database()
        console.print(Panel.fit(
            "[green]✓[/green] Database initialized successfully!",
            title="Initialization Complete"
        ))
    except Exception as e:
        console.print(Panel.fit(
            f"[red]✗[/red] Failed to initialize database: {e}",
            title="Initialization Failed"
        ))
        sys.exit(1)

@cli.command()
@click.option('--key-file', '-k', required=True, help='Path to the GPG key file')
@click.option('--owner', '-o', required=True, help='Key owner name')
@click.option('--requester', '-r', required=True, help='Person who requested the key')
@click.option('--jira-ticket', '-j', help='JIRA ticket number')
@click.option('--notes', '-n', help='Additional notes')
def add_key(key_file, owner, requester, jira_ticket, notes):
    """Add a new GPG key to the tracker"""
    if not os.path.exists(key_file):
        console.print(f"[red]Error:[/red] Key file '{key_file}' not found")
        sys.exit(1)
    
    gpg_manager = GPGManager()
    
    try:
        success = gpg_manager.add_key(
            key_file=key_file,
            owner=owner,
            requester=requester,
            jira_ticket=jira_ticket,
            notes=notes
        )
        
        if success:
            console.print(Panel.fit(
                f"[green]✓[/green] Key added successfully!\n"
                f"Owner: {owner}\n"
                f"Requester: {requester}\n"
                f"JIRA Ticket: {jira_ticket or 'N/A'}",
                title="Key Added"
            ))
        else:
            console.print(Panel.fit(
                "[red]✗[/red] Failed to add key",
                title="Error"
            ))
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--fingerprint', '-f', required=True, help='Key fingerprint')
def delete_key(fingerprint):
    """Delete a GPG key from the tracker"""
    gpg_manager = GPGManager()
    
    # Confirm deletion
    key_info = gpg_manager.get_key_by_fingerprint(fingerprint)
    if not key_info:
        console.print(f"[red]Error:[/red] Key with fingerprint '{fingerprint}' not found")
        sys.exit(1)
    
    console.print(f"About to delete key:")
    console.print(f"  Fingerprint: {key_info['fingerprint']}")
    console.print(f"  Owner: {key_info['owner']}")
    console.print(f"  Email: {key_info['email'] or 'N/A'}")
    
    if not click.confirm("Are you sure you want to delete this key?"):
        console.print("Deletion cancelled")
        return
    
    try:
        success = gpg_manager.delete_key(fingerprint)
        
        if success:
            console.print(Panel.fit(
                "[green]✓[/green] Key deleted successfully!",
                title="Key Deleted"
            ))
        else:
            console.print(Panel.fit(
                "[red]✗[/red] Failed to delete key",
                title="Error"
            ))
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--fingerprint', '-f', required=True, help='Key fingerprint')
def activate_key(fingerprint):
    """Activate a deactivated key"""
    gpg_manager = GPGManager()
    
    # Check if key exists
    key_info = gpg_manager.get_key_by_fingerprint(fingerprint)
    if not key_info:
        console.print(f"[red]Error:[/red] Key with fingerprint '{fingerprint}' not found")
        sys.exit(1)
    
    try:
        success = gpg_manager.activate_key(fingerprint)
        
        if success:
            console.print(Panel.fit(
                "[green]✓[/green] Key activated successfully!",
                title="Key Activated"
            ))
        else:
            console.print(Panel.fit(
                "[red]✗[/red] Failed to activate key",
                title="Error"
            ))
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--fingerprint', '-f', required=True, help='Key fingerprint')
def deactivate_key(fingerprint):
    """Deactivate an active key"""
    gpg_manager = GPGManager()
    
    # Check if key exists
    key_info = gpg_manager.get_key_by_fingerprint(fingerprint)
    if not key_info:
        console.print(f"[red]Error:[/red] Key with fingerprint '{fingerprint}' not found")
        sys.exit(1)
    
    console.print(f"About to deactivate key:")
    console.print(f"  Fingerprint: {key_info['fingerprint']}")
    console.print(f"  Owner: {key_info['owner']}")
    console.print(f"  Email: {key_info['email'] or 'N/A'}")
    
    if not click.confirm("Are you sure you want to deactivate this key?"):
        console.print("Deactivation cancelled")
        return
    
    try:
        success = gpg_manager.deactivate_key(fingerprint)
        
        if success:
            console.print(Panel.fit(
                "[green]✓[/green] Key deactivated successfully!",
                title="Key Deactivated"
            ))
        else:
            console.print(Panel.fit(
                "[red]✗[/red] Failed to deactivate key",
                title="Error"
            ))
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--old-fingerprint', '-o', required=True, help='Fingerprint of key to replace')
@click.option('--new-key-file', '-n', required=True, help='Path to the new key file')
@click.option('--owner', help='New owner name (optional)')
@click.option('--requester', help='New requester name (optional)')
@click.option('--jira-ticket', help='New JIRA ticket number (optional)')
@click.option('--notes', help='Additional notes (optional)')
@click.option('--delete-old', is_flag=True, help='Delete old key from keyring after replacement')
def replace_key(old_fingerprint, new_key_file, owner, requester, jira_ticket, notes, delete_old):
    """Replace an existing key with a new one"""
    if not os.path.exists(new_key_file):
        console.print(f"[red]Error:[/red] New key file '{new_key_file}' not found")
        sys.exit(1)
    
    gpg_manager = GPGManager()
    
    # Check if old key exists
    old_key_info = gpg_manager.get_key_by_fingerprint(old_fingerprint)
    if not old_key_info:
        console.print(f"[red]Error:[/red] Key with fingerprint '{old_fingerprint}' not found")
        sys.exit(1)
    
    console.print(f"About to replace key:")
    console.print(f"  Old Fingerprint: {old_key_info['fingerprint']}")
    console.print(f"  Owner: {old_key_info['owner']}")
    console.print(f"  New Key File: {new_key_file}")
    if delete_old:
        console.print(f"  [yellow]Warning:[/yellow] Old key will be deleted from keyring")
    
    if not click.confirm("Are you sure you want to replace this key?"):
        console.print("Replacement cancelled")
        return
    
    try:
        success = gpg_manager.replace_key(
            old_fingerprint=old_fingerprint,
            new_key_file=new_key_file,
            owner=owner,
            requester=requester,
            jira_ticket=jira_ticket,
            notes=notes,
            delete_old=delete_old
        )
        
        if success:
            console.print(Panel.fit(
                "[green]✓[/green] Key replaced successfully!",
                title="Key Replaced"
            ))
        else:
            console.print(Panel.fit(
                "[red]✗[/red] Failed to replace key",
                title="Error"
            ))
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--fingerprint', '-f', required=True, help='Key fingerprint')
@click.option('--owner', '-o', help='New owner name')
@click.option('--requester', '-r', help='New requester name')
@click.option('--jira-ticket', '-j', help='New JIRA ticket number')
@click.option('--notes', '-n', help='New notes')
def edit_key(fingerprint, owner, requester, jira_ticket, notes):
    """Edit key metadata"""
    gpg_manager = GPGManager()
    
    # Check if key exists
    key_info = gpg_manager.get_key_by_fingerprint(fingerprint)
    if not key_info:
        console.print(f"[red]Error:[/red] Key with fingerprint '{fingerprint}' not found")
        sys.exit(1)
    
    # Build update dictionary
    updates = {}
    if owner:
        updates['owner'] = owner
    if requester:
        updates['requester'] = requester
    if jira_ticket:
        updates['jira_ticket'] = jira_ticket
    if notes:
        updates['notes'] = notes
    
    if not updates:
        console.print("[yellow]Warning:[/yellow] No changes specified")
        return
    
    try:
        success = gpg_manager.edit_key(fingerprint, **updates)
        
        if success:
            console.print(Panel.fit(
                "[green]✓[/green] Key updated successfully!",
                title="Key Updated"
            ))
        else:
            console.print(Panel.fit(
                "[red]✗[/red] Failed to update key",
                title="Error"
            ))
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--fingerprint', '-f', help='Filter by key fingerprint')
@click.option('--all', '-a', is_flag=True, help='Show all keys including inactive ones')
def list_keys(fingerprint, all):
    """List tracked GPG keys"""
    gpg_manager = GPGManager()
    
    try:
        keys = gpg_manager.list_keys(include_inactive=all)
        
        if not keys:
            console.print(Panel.fit(
                "No keys found in the tracker",
                title="No Keys"
            ))
            return
        
        # Filter by fingerprint if specified
        if fingerprint:
            keys = [k for k in keys if fingerprint.lower() in k['fingerprint'].lower()]
        
        if not keys:
            console.print(Panel.fit(
                f"No keys found matching fingerprint '{fingerprint}'",
                title="No Matching Keys"
            ))
            return
        
        # Create table
        table = Table(title="GPG Keys")
        table.add_column("Status", style="bold")
        table.add_column("Fingerprint", style="cyan", no_wrap=True)
        table.add_column("Key ID", style="blue")
        table.add_column("Name", style="green")
        table.add_column("Email", style="yellow")
        table.add_column("Owner", style="magenta")
        table.add_column("Requester", style="white")
        table.add_column("JIRA Ticket", style="red")
        table.add_column("Created", style="dim")
        
        for key in keys:
            status = "[green]✓[/green]" if key['is_active'] else "[red]✗[/red]"
            table.add_row(
                status,
                key['fingerprint'][:16] + "...",
                key['key_id'],
                key['name'] or 'N/A',
                key['email'] or 'N/A',
                key['owner'],
                key['requester'],
                key['jira_ticket'] or 'N/A',
                key['created_at'].strftime('%Y-%m-%d')
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--fingerprint', '-f', help='Filter logs by key fingerprint')
@click.option('--limit', '-l', default=50, help='Number of logs to show')
def logs(fingerprint, limit):
    """Show usage logs"""
    gpg_manager = GPGManager()
    
    try:
        logs = gpg_manager.get_usage_logs(fingerprint, limit)
        
        if not logs:
            console.print(Panel.fit(
                "No usage logs found",
                title="No Logs"
            ))
            return
        
        # Create table
        table = Table(title="Usage Logs")
        table.add_column("Timestamp", style="dim")
        table.add_column("Operation", style="cyan")
        table.add_column("User", style="green")
        table.add_column("Fingerprint", style="blue", no_wrap=True)
        table.add_column("File", style="yellow")
        table.add_column("Recipient", style="magenta")
        table.add_column("Status", style="bold")
        
        for log in logs:
            status_style = "green" if log['success'] else "red"
            status_text = "✓" if log['success'] else "✗"
            
            table.add_row(
                log['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                log['operation'],
                log['user'],
                log['fingerprint'][:16] + "...",
                log['file_path'] or 'N/A',
                log['recipient'] or 'N/A',
                f"[{status_style}]{status_text}[/{status_style}]"
            )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--fingerprint', '-f', required=True, help='Key fingerprint')
def key_info(fingerprint):
    """Show detailed information about a specific key"""
    gpg_manager = GPGManager()
    
    try:
        key_info = gpg_manager.get_key_by_fingerprint(fingerprint)
        
        if not key_info:
            console.print(f"[red]Error:[/red] Key with fingerprint '{fingerprint}' not found")
            sys.exit(1)
        
        # Create detailed info panel
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

[bright_magenta]Notes:[/bright_magenta]
{key_info['notes'] or 'No notes'}
        """
        
        console.print(Panel(info_text, title="Key Details"))
        
        # Show recent usage logs
        logs = gpg_manager.get_usage_logs(fingerprint, 10)
        if logs:
            console.print("\n[bold]Recent Usage:[/bold]")
            log_table = Table()
            log_table.add_column("Timestamp", style="dim")
            log_table.add_column("Operation", style="cyan")
            log_table.add_column("User", style="green")
            log_table.add_column("File", style="yellow")
            log_table.add_column("Status", style="bold")
            
            for log in logs:
                status_style = "green" if log['success'] else "red"
                status_text = "✓" if log['success'] else "✗"
                
                log_table.add_row(
                    log['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    log['operation'],
                    log['user'],
                    log['file_path'] or 'N/A',
                    f"[{status_style}]{status_text}[/{status_style}]"
                )
            
            console.print(log_table)
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--days', '-d', default=30, help='Number of days to include in report')
@click.option('--fingerprint', '-f', help='Filter by specific key fingerprint')
@click.option('--format', 'report_format', type=click.Choice(['csv', 'json', 'html']), default='csv', help='Report format')
@click.option('--output', '-o', help='Output file path (optional)')
def generate_report(days, fingerprint, report_format, output):
    """Generate a GPG key usage report"""
    try:
        generator = ReportGenerator()
        
        # Generate report data
        console.print(f"Generating report for the last {days} days...")
        report_data = generator.generate_usage_report(days=days, key_fingerprint=fingerprint)
        
        # Generate output file
        if not output:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output = f"gpg_usage_report_{timestamp}.{report_format}"
        
        # Export based on format
        if report_format == 'csv':
            generator.export_to_csv(report_data, output)
        elif report_format == 'json':
            generator.export_to_json(report_data, output)
        elif report_format == 'html':
            generator.export_to_html(report_data, output)
        
        console.print(Panel.fit(
            f"[green]✓[/green] Report generated successfully!\n"
            f"File: {output}\n"
            f"Format: {report_format.upper()}\n"
            f"Period: {days} days\n"
            f"Total Operations: {report_data['total_operations']}\n"
            f"Success Rate: {report_data['success_rate']:.2f}%",
            title="Report Generated"
        ))
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--report-file', '-r', required=True, help='Path to the report file')
@click.option('--recipients', '-e', required=True, help='Comma-separated list of email addresses')
@click.option('--subject', '-s', help='Email subject (optional)')
@click.option('--body', '-b', help='Email body (optional)')
def email_report(report_file, recipients, subject, body):
    """Email a report to specified recipients"""
    if not os.path.exists(report_file):
        console.print(f"[red]Error:[/red] Report file '{report_file}' not found")
        sys.exit(1)
    
    try:
        exporter = ReportExporter()
        recipient_list = [email.strip() for email in recipients.split(',')]
        
        console.print(f"Sending report to {len(recipient_list)} recipient(s)...")
        success = exporter.send_email_report(report_file, recipient_list, subject, body)
        
        if success:
            console.print(Panel.fit(
                f"[green]✓[/green] Report sent successfully!\n"
                f"Recipients: {', '.join(recipient_list)}",
                title="Report Sent"
            ))
        else:
            console.print(Panel.fit(
                "[red]✗[/red] Failed to send report",
                title="Error"
            ))
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--report-file', '-r', required=True, help='Path to the report file')
@click.option('--bucket', '-b', required=True, help='S3 bucket name')
@click.option('--key', '-k', help='S3 object key (optional)')
def upload_to_s3(report_file, bucket, key):
    """Upload a report to S3 bucket"""
    if not os.path.exists(report_file):
        console.print(f"[red]Error:[/red] Report file '{report_file}' not found")
        sys.exit(1)
    
    try:
        exporter = ReportExporter()
        
        console.print(f"Uploading report to S3 bucket '{bucket}'...")
        success = exporter.upload_to_s3(report_file, bucket, key)
        
        if success:
            console.print(Panel.fit(
                f"[green]✓[/green] Report uploaded successfully!\n"
                f"Bucket: {bucket}\n"
                f"File: {report_file}",
                title="Report Uploaded"
            ))
        else:
            console.print(Panel.fit(
                "[red]✗[/red] Failed to upload report",
                title="Error"
            ))
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--report-file', '-r', required=True, help='Path to the report file')
@click.option('--host', '-h', required=True, help='Remote host address')
@click.option('--path', '-p', required=True, help='Remote directory path')
@click.option('--username', '-u', help='SSH username (optional)')
@click.option('--password', help='SSH password (optional)')
@click.option('--key-file', help='SSH private key file (optional)')
def scp_report(report_file, host, path, username, password, key_file):
    """Upload a report to remote server via SCP"""
    if not os.path.exists(report_file):
        console.print(f"[red]Error:[/red] Report file '{report_file}' not found")
        sys.exit(1)
    
    try:
        exporter = ReportExporter()
        
        console.print(f"Uploading report to {host}:{path}...")
        success = exporter.scp_to_remote(report_file, host, path, username, password, key_file)
        
        if success:
            console.print(Panel.fit(
                f"[green]✓[/green] Report uploaded successfully!\n"
                f"Host: {host}\n"
                f"Path: {path}\n"
                f"File: {report_file}",
                title="Report Uploaded"
            ))
        else:
            console.print(Panel.fit(
                "[red]✗[/red] Failed to upload report",
                title="Error"
            ))
            sys.exit(1)
            
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--days', '-d', default=30, help='Number of days to include in report')
@click.option('--fingerprint', '-f', help='Filter by specific key fingerprint')
@click.option('--format', 'report_format', type=click.Choice(['csv', 'json', 'html']), default='csv', help='Report format')
@click.option('--recipients', '-e', help='Comma-separated list of email addresses')
@click.option('--s3-bucket', help='S3 bucket name')
@click.option('--scp-host', help='Remote host for SCP upload')
@click.option('--scp-path', help='Remote path for SCP upload')
@click.option('--email-subject', help='Email subject')
@click.option('--email-body', help='Email body')
def auto_report(days, fingerprint, report_format, recipients, s3_bucket, scp_host, scp_path, email_subject, email_body):
    """Generate and automatically export a report"""
    try:
        generator = ReportGenerator()
        exporter = ReportExporter()
        
        # Generate report
        console.print(f"Generating {report_format.upper()} report for the last {days} days...")
        report_data = generator.generate_usage_report(days=days, key_fingerprint=fingerprint)
        
        # Create temporary file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        temp_file = f"gpg_usage_report_{timestamp}.{report_format}"
        
        # Export based on format
        if report_format == 'csv':
            generator.export_to_csv(report_data, temp_file)
        elif report_format == 'json':
            generator.export_to_json(report_data, temp_file)
        elif report_format == 'html':
            generator.export_to_html(report_data, temp_file)
        
        console.print(f"[green]✓[/green] Report generated: {temp_file}")
        
        # Export via email
        if recipients:
            recipient_list = [email.strip() for email in recipients.split(',')]
            console.print(f"Sending report to {len(recipient_list)} recipient(s)...")
            email_success = exporter.send_email_report(temp_file, recipient_list, email_subject, email_body)
            if email_success:
                console.print("[green]✓[/green] Report sent via email")
            else:
                console.print("[red]✗[/red] Failed to send email")
        
        # Export via S3
        if s3_bucket:
            console.print(f"Uploading report to S3 bucket '{s3_bucket}'...")
            s3_success = exporter.upload_to_s3(temp_file, s3_bucket)
            if s3_success:
                console.print("[green]✓[/green] Report uploaded to S3")
            else:
                console.print("[red]✗[/red] Failed to upload to S3")
        
        # Export via SCP
        if scp_host and scp_path:
            console.print(f"Uploading report to {scp_host}:{scp_path}...")
            scp_success = exporter.scp_to_remote(temp_file, scp_host, scp_path)
            if scp_success:
                console.print("[green]✓[/green] Report uploaded via SCP")
            else:
                console.print("[red]✗[/red] Failed to upload via SCP")
        
        # Clean up temporary file if no local output requested
        if not any([recipients, s3_bucket, scp_host]):
            os.remove(temp_file)
            console.print(f"Temporary file {temp_file} removed")
        
        console.print(Panel.fit(
            f"[green]✓[/green] Auto-report completed!\n"
            f"Format: {report_format.upper()}\n"
            f"Period: {days} days\n"
            f"Total Operations: {report_data['total_operations']}\n"
            f"Success Rate: {report_data['success_rate']:.2f}%",
            title="Auto-Report Complete"
        ))
        
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--name', '-n', help='Backup name (optional, auto-generated if not provided)')
def create_backup(name):
    """Create a full backup of GPG keys and database"""
    try:
        backup_manager = BackupManager()
        console.print("Creating backup...")

        backup_info = backup_manager.create_full_backup(name)

        console.print(Panel.fit(
            f"[green]✓[/green] Backup created successfully!\n"
            f"Name: {backup_info['backup_name']}\n"
            f"Components: {', '.join(backup_info['components'].keys())}\n"
            f"Timestamp: {backup_info['timestamp']}",
            title="Backup Created"
        ))

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
def list_backups():
    """List available backups"""
    try:
        backup_manager = BackupManager()
        backups = backup_manager.list_backups()

        if not backups:
            console.print(Panel.fit(
                "No backups found",
                title="No Backups"
            ))
            return

        # Create table
        table = Table(title="Available Backups")
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Type", style="blue")
        table.add_column("Size", style="green")
        table.add_column("Created", style="yellow")
        table.add_column("Components", style="magenta")

        for backup in backups:
            size_mb = backup.get('size', 0) / (1024 * 1024)
            components = list(backup.get('components', {}).keys())

            table.add_row(
                backup['name'],
                backup.get('type', 'unknown'),
                f"{size_mb:.2f} MB",
                backup.get('created', 'unknown').strftime('%Y-%m-%d %H:%M:%S'),
                ', '.join(components) if components else 'N/A'
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--backup-name', '-b', required=True, help='Name of backup to restore')
@click.option('--components', '-c', help='Comma-separated list of components to restore (database,gpg_keyring)')
@click.confirmation_option(prompt='Are you sure you want to restore? This will overwrite current data.')
def restore_backup(backup_name, components):
    """Restore from a backup"""
    try:
        backup_manager = BackupManager()

        component_list = None
        if components:
            component_list = [c.strip() for c in components.split(',')]

        console.print(f"Restoring from backup: {backup_name}...")

        restore_result = backup_manager.restore_from_backup(backup_name, component_list)

        console.print(Panel.fit(
            f"[green]✓[/green] Restore completed!\n"
            f"Backup: {restore_result['backup_name']}\n"
            f"Components restored: {', '.join(restore_result['components'].keys())}\n"
            f"Timestamp: {restore_result['restore_timestamp']}",
            title="Restore Completed"
        ))

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--backup-name', '-b', required=True, help='Name of backup to delete')
@click.confirmation_option(prompt='Are you sure you want to delete this backup?')
def delete_backup(backup_name):
    """Delete a backup"""
    try:
        backup_manager = BackupManager()

        if backup_manager.delete_backup(backup_name):
            console.print(Panel.fit(
                f"[green]✓[/green] Backup deleted successfully!\n"
                f"Name: {backup_name}",
                title="Backup Deleted"
            ))
        else:
            console.print(Panel.fit(
                f"[red]✗[/red] Failed to delete backup: {backup_name}",
                title="Error"
            ))
            sys.exit(1)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--days', '-d', default=30, help='Number of days ahead to check for expiring keys')
def expiring_keys(days):
    """Show keys that will expire within the specified number of days"""
    gpg_manager = GPGManager()

    try:
        expiring = gpg_manager.get_expiring_keys(days)

        if not expiring:
            console.print(Panel.fit(
                f"No keys expiring within {days} days",
                title="No Expiring Keys"
            ))
            return

        # Create table
        table = Table(title=f"Keys Expiring Within {days} Days")
        table.add_column("Fingerprint", style="cyan", no_wrap=True)
        table.add_column("Owner", style="green")
        table.add_column("Email", style="yellow")
        table.add_column("Expires", style="red")
        table.add_column("Days Left", style="bold red")
        table.add_column("Usage Count", style="blue")

        for key in expiring:
            days_left = key['days_until_expiry']
            style = "bold red" if days_left <= 7 else "yellow" if days_left <= 30 else "green"

            table.add_row(
                key['fingerprint'][:16] + "...",
                key['owner'],
                key['email'] or 'N/A',
                key['expires_at'].strftime('%Y-%m-%d'),
                f"[{style}]{days_left}[/{style}]",
                str(key['usage_count'] or 0)
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
def expired_keys():
    """Show keys that have already expired"""
    gpg_manager = GPGManager()

    try:
        expired = gpg_manager.get_expired_keys()

        if not expired:
            console.print(Panel.fit(
                "No expired keys found",
                title="No Expired Keys"
            ))
            return

        # Create table
        table = Table(title="Expired Keys")
        table.add_column("Fingerprint", style="cyan", no_wrap=True)
        table.add_column("Owner", style="green")
        table.add_column("Email", style="yellow")
        table.add_column("Expired", style="red")
        table.add_column("Days Ago", style="bold red")
        table.add_column("Usage Count", style="blue")

        for key in expired:
            table.add_row(
                key['fingerprint'][:16] + "...",
                key['owner'],
                key['email'] or 'N/A',
                key['expires_at'].strftime('%Y-%m-%d'),
                str(key['days_since_expiry']),
                str(key['usage_count'] or 0)
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
def update_expiry():
    """Update expiry status for all keys"""
    gpg_manager = GPGManager()

    try:
        console.print("Refreshing key expiry dates from GPG...")
        refreshed = gpg_manager.refresh_key_expiry_dates()

        console.print("Updating key expiry status...")
        updated = gpg_manager.update_key_expiry_status()

        console.print(Panel.fit(
            f"[green]✓[/green] Expiry update completed!\n"
            f"Keys refreshed: {refreshed}\n"
            f"Keys updated: {updated}",
            title="Expiry Update Complete"
        ))

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
def health_check():
    """Check system health"""
    try:
        health_checker = get_health_checker()
        health_status = health_checker.get_overall_health()

        # Display overall status
        status_color = "green" if health_status['status'] == 'healthy' else "yellow" if health_status['status'] == 'degraded' else "red"
        console.print(Panel.fit(
            f"[{status_color}]{health_status['status'].upper()}[/{status_color}]\n"
            f"Timestamp: {health_status['timestamp']}\n"
            f"Healthy: {health_status['summary']['healthy']}\n"
            f"Degraded: {health_status['summary']['degraded']}\n"
            f"Unhealthy: {health_status['summary']['unhealthy']}",
            title="System Health"
        ))

        # Display individual checks
        table = Table(title="Health Check Details")
        table.add_column("Service", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Response Time", style="blue")
        table.add_column("Details", style="dim")

        for service, check in health_status['checks'].items():
            status_style = "green" if check['status'] == 'healthy' else "yellow" if check['status'] == 'degraded' else "red"
            response_time = f"{check.get('response_time_ms', 0):.2f}ms"

            # Format details
            details = check.get('details', {})
            detail_str = ', '.join([f"{k}: {v}" for k, v in details.items() if k != 'error'])
            if 'error' in details:
                detail_str = f"Error: {details['error']}"

            table.add_row(
                service.title(),
                f"[{status_style}]{check['status'].upper()}[/{status_style}]",
                response_time,
                detail_str[:50] + "..." if len(detail_str) > 50 else detail_str
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
def metrics():
    """Show system metrics"""
    try:
        metrics_collector = get_metrics_collector()
        current_metrics = metrics_collector.get_current_metrics()
        uptime = metrics_collector.get_system_uptime()

        # Display key metrics
        console.print(Panel.fit(
            f"[bright_blue]Keys:[/bright_blue] {current_metrics.total_keys} total, {current_metrics.active_keys} active, {current_metrics.expired_keys} expired\n"
            f"[bright_green]Operations:[/bright_green] {current_metrics.total_operations} total, {current_metrics.success_rate:.2f}% success rate\n"
            f"[bright_yellow]Performance:[/bright_yellow] {current_metrics.avg_response_time_ms:.2f}ms avg response time\n"
            f"[bright_magenta]Uptime:[/bright_magenta] {uptime/3600:.2f} hours\n"
            f"[bright_cyan]Database:[/bright_cyan] {current_metrics.database_size_mb:.2f}MB" if current_metrics.database_size_mb else "",
            title="System Metrics"
        ))

        # Operations by type (last 24 hours)
        if current_metrics.operations_by_type:
            table = Table(title="Operations by Type (Last 24 Hours)")
            table.add_column("Operation", style="cyan")
            table.add_column("Count", style="green", justify="right")

            for operation, count in sorted(current_metrics.operations_by_type.items(), key=lambda x: x[1], reverse=True):
                table.add_row(operation.capitalize(), str(count))

            console.print(table)

        # Top users (last 24 hours)
        if current_metrics.operations_by_user:
            table = Table(title="Top Users (Last 24 Hours)")
            table.add_column("User", style="cyan")
            table.add_column("Operations", style="green", justify="right")

            # Show top 10 users
            top_users = sorted(current_metrics.operations_by_user.items(), key=lambda x: x[1], reverse=True)[:10]
            for user, count in top_users:
                table.add_row(user, str(count))

            console.print(table)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.option('--format', 'output_format', type=click.Choice(['json', 'table']), default='table', help='Output format')
def export_metrics(output_format):
    """Export system metrics"""
    try:
        metrics_collector = get_metrics_collector()

        if output_format == 'json':
            metrics_json = metrics_collector.export_metrics_json()
            console.print(metrics_json)
        else:
            # Use the regular metrics command for table format
            from click import Context
            ctx = Context(metrics)
            ctx.invoke(metrics)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
def interactive():
    """Start interactive mode"""
    start_interactive_mode()

if __name__ == '__main__':
    cli()
