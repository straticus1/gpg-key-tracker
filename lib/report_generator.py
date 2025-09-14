#!/usr/bin/env python3
"""
GPG Key Tracker - Report Generator
"""

import os
import csv
import json
import smtplib
import tempfile
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Dict, Optional, Any
import boto3
import paramiko
from jinja2 import Template
from gpg_manager import GPGManager
from dotenv import load_dotenv

load_dotenv()

class ReportGenerator:
    """Generates and exports GPG key usage reports"""
    
    def __init__(self):
        """Initialize report generator"""
        self.gpg_manager = GPGManager()
    
    def generate_usage_report(self, days: int = 30, key_fingerprint: Optional[str] = None) -> Dict[str, Any]:
        """Generate a comprehensive usage report"""
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        # Get usage logs
        logs = self.gpg_manager.get_usage_logs(fingerprint=key_fingerprint, limit=10000)
        
        # Filter by date range
        filtered_logs = [
            log for log in logs 
            if start_date <= log['timestamp'] <= end_date
        ]
        
        # Get all keys for reference
        all_keys = self.gpg_manager.list_keys(include_inactive=True)
        key_map = {key['fingerprint']: key for key in all_keys}
        
        # Generate statistics
        total_operations = len(filtered_logs)
        successful_operations = len([log for log in filtered_logs if log['success']])
        failed_operations = total_operations - successful_operations
        
        # Operations by type
        operations_by_type = {}
        for log in filtered_logs:
            op_type = log['operation']
            operations_by_type[op_type] = operations_by_type.get(op_type, 0) + 1
        
        # Operations by user
        operations_by_user = {}
        for log in filtered_logs:
            user = log['user']
            operations_by_user[user] = operations_by_user.get(user, 0) + 1
        
        # Operations by key
        operations_by_key = {}
        for log in filtered_logs:
            fingerprint = log['fingerprint']
            key_info = key_map.get(fingerprint, {'owner': 'Unknown', 'email': 'Unknown'})
            key_name = f"{key_info['owner']} ({fingerprint[:16]}...)"
            operations_by_key[key_name] = operations_by_key.get(key_name, 0) + 1
        
        return {
            'report_date': datetime.utcnow(),
            'period_start': start_date,
            'period_end': end_date,
            'days_covered': days,
            'total_operations': total_operations,
            'successful_operations': successful_operations,
            'failed_operations': failed_operations,
            'success_rate': (successful_operations / total_operations * 100) if total_operations > 0 else 0,
            'operations_by_type': operations_by_type,
            'operations_by_user': operations_by_user,
            'operations_by_key': operations_by_key,
            'detailed_logs': filtered_logs,
            'key_fingerprint_filter': key_fingerprint
        }
    
    def export_to_csv(self, report_data: Dict[str, Any], output_file: str) -> str:
        """Export report to CSV format"""
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write summary
            writer.writerow(['GPG Key Usage Report'])
            writer.writerow(['Report Date', report_data['report_date'].strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow(['Period Start', report_data['period_start'].strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow(['Period End', report_data['period_end'].strftime('%Y-%m-%d %H:%M:%S')])
            writer.writerow(['Days Covered', report_data['days_covered']])
            writer.writerow([])
            
            # Write statistics
            writer.writerow(['Statistics'])
            writer.writerow(['Total Operations', report_data['total_operations']])
            writer.writerow(['Successful Operations', report_data['successful_operations']])
            writer.writerow(['Failed Operations', report_data['failed_operations']])
            writer.writerow(['Success Rate (%)', f"{report_data['success_rate']:.2f}"])
            writer.writerow([])
            
            # Write operations by type
            writer.writerow(['Operations by Type'])
            for op_type, count in report_data['operations_by_type'].items():
                writer.writerow([op_type, count])
            writer.writerow([])
            
            # Write operations by user
            writer.writerow(['Operations by User'])
            for user, count in report_data['operations_by_user'].items():
                writer.writerow([user, count])
            writer.writerow([])
            
            # Write operations by key
            writer.writerow(['Operations by Key'])
            for key_name, count in report_data['operations_by_key'].items():
                writer.writerow([key_name, count])
            writer.writerow([])
            
            # Write detailed logs
            writer.writerow(['Detailed Logs'])
            writer.writerow(['Timestamp', 'Operation', 'User', 'Fingerprint', 'File', 'Recipient', 'Success', 'Error'])
            for log in report_data['detailed_logs']:
                writer.writerow([
                    log['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    log['operation'],
                    log['user'],
                    log['fingerprint'][:16] + '...',
                    log['file_path'] or 'N/A',
                    log['recipient'] or 'N/A',
                    'Yes' if log['success'] else 'No',
                    log['error_message'] or 'N/A'
                ])
        
        return output_file
    
    def export_to_json(self, report_data: Dict[str, Any], output_file: str) -> str:
        """Export report to JSON format"""
        # Convert datetime objects to strings for JSON serialization
        json_data = {
            'report_date': report_data['report_date'].isoformat(),
            'period_start': report_data['period_start'].isoformat(),
            'period_end': report_data['period_end'].isoformat(),
            'days_covered': report_data['days_covered'],
            'total_operations': report_data['total_operations'],
            'successful_operations': report_data['successful_operations'],
            'failed_operations': report_data['failed_operations'],
            'success_rate': report_data['success_rate'],
            'operations_by_type': report_data['operations_by_type'],
            'operations_by_user': report_data['operations_by_user'],
            'operations_by_key': report_data['operations_by_key'],
            'detailed_logs': [
                {
                    'timestamp': log['timestamp'].isoformat(),
                    'operation': log['operation'],
                    'user': log['user'],
                    'fingerprint': log['fingerprint'],
                    'file_path': log['file_path'],
                    'recipient': log['recipient'],
                    'success': log['success'],
                    'error_message': log['error_message']
                }
                for log in report_data['detailed_logs']
            ],
            'key_fingerprint_filter': report_data['key_fingerprint_filter']
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        return output_file
    
    def export_to_html(self, report_data: Dict[str, Any], output_file: str) -> str:
        """Export report to HTML format"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>GPG Key Usage Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; }
        .stats { display: flex; gap: 20px; }
        .stat-box { background-color: #e8f4fd; padding: 15px; border-radius: 5px; flex: 1; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .success { color: green; }
        .failure { color: red; }
        .warning { color: orange; }
    </style>
</head>
<body>
    <div class="header">
        <h1>GPG Key Usage Report</h1>
        <p><strong>Report Date:</strong> {{ report_date.strftime('%Y-%m-%d %H:%M:%S') }}</p>
        <p><strong>Period:</strong> {{ period_start.strftime('%Y-%m-%d %H:%M:%S') }} to {{ period_end.strftime('%Y-%m-%d %H:%M:%S') }}</p>
        <p><strong>Days Covered:</strong> {{ days_covered }}</p>
    </div>

    <div class="section">
        <h2>Summary Statistics</h2>
        <div class="stats">
            <div class="stat-box">
                <h3>Total Operations</h3>
                <p style="font-size: 24px; font-weight: bold;">{{ total_operations }}</p>
            </div>
            <div class="stat-box">
                <h3>Successful</h3>
                <p style="font-size: 24px; font-weight: bold; color: green;">{{ successful_operations }}</p>
            </div>
            <div class="stat-box">
                <h3>Failed</h3>
                <p style="font-size: 24px; font-weight: bold; color: red;">{{ failed_operations }}</p>
            </div>
            <div class="stat-box">
                <h3>Success Rate</h3>
                <p style="font-size: 24px; font-weight: bold; color: blue;">{{ "%.2f"|format(success_rate) }}%</p>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Operations by Type</h2>
        <table>
            <tr><th>Operation Type</th><th>Count</th></tr>
            {% for op_type, count in operations_by_type.items() %}
            <tr><td>{{ op_type }}</td><td>{{ count }}</td></tr>
            {% endfor %}
        </table>
    </div>

    <div class="section">
        <h2>Operations by User</h2>
        <table>
            <tr><th>User</th><th>Count</th></tr>
            {% for user, count in operations_by_user.items() %}
            <tr><td>{{ user }}</td><td>{{ count }}</td></tr>
            {% endfor %}
        </table>
    </div>

    <div class="section">
        <h2>Operations by Key</h2>
        <table>
            <tr><th>Key</th><th>Count</th></tr>
            {% for key_name, count in operations_by_key.items() %}
            <tr><td>{{ key_name }}</td><td>{{ count }}</td></tr>
            {% endfor %}
        </table>
    </div>

    <div class="section">
        <h2>Detailed Logs</h2>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Operation</th>
                <th>User</th>
                <th>Fingerprint</th>
                <th>File</th>
                <th>Recipient</th>
                <th>Status</th>
            </tr>
            {% for log in detailed_logs %}
            <tr>
                <td>{{ log.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                <td>{{ log.operation }}</td>
                <td>{{ log.user }}</td>
                <td>{{ log.fingerprint[:16] }}...</td>
                <td>{{ log.file_path or 'N/A' }}</td>
                <td>{{ log.recipient or 'N/A' }}</td>
                <td class="{{ 'success' if log.success else 'failure' }}">
                    {{ '✓' if log.success else '✗' }}
                </td>
            </tr>
            {% endfor %}
        </table>
    </div>
</body>
</html>
        """
        
        template = Template(html_template)
        html_content = template.render(**report_data)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file

class ReportExporter:
    """Handles exporting reports via email, S3, or SCP"""
    
    def __init__(self):
        """Initialize report exporter"""
        load_dotenv()
    
    def send_email_report(self, report_file: str, recipients: List[str], 
                         subject: Optional[str] = None, body: Optional[str] = None) -> bool:
        """Send report via email"""
        try:
            # Email configuration
            smtp_server = os.getenv('SMTP_SERVER', 'localhost')
            smtp_port = int(os.getenv('SMTP_PORT', '587'))
            smtp_username = os.getenv('SMTP_USERNAME')
            smtp_password = os.getenv('SMTP_PASSWORD')
            from_email = os.getenv('FROM_EMAIL', 'gpg-tracker@example.com')
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = subject or f"GPG Key Usage Report - {datetime.now().strftime('%Y-%m-%d')}"
            
            # Add body
            body_text = body or f"""
GPG Key Usage Report

This report contains GPG key usage statistics and detailed logs.
Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Please find the attached report for your review.
            """
            msg.attach(MIMEText(body_text, 'plain'))
            
            # Attach report file
            with open(report_file, 'rb') as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
            
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {os.path.basename(report_file)}'
            )
            msg.attach(part)
            
            # Send email
            server = smtplib.SMTP(smtp_server, smtp_port)
            if smtp_username and smtp_password:
                server.starttls()
                server.login(smtp_username, smtp_password)
            
            text = msg.as_string()
            server.sendmail(from_email, recipients, text)
            server.quit()
            
            return True
            
        except Exception as e:
            print(f"Error sending email: {e}")
            return False
    
    def upload_to_s3(self, report_file: str, bucket: str, key: Optional[str] = None) -> bool:
        """Upload report to S3 bucket"""
        try:
            # S3 configuration
            aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
            aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')
            aws_region = os.getenv('AWS_REGION', 'us-east-1')
            
            # Create S3 client
            s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=aws_region
            )
            
            # Generate key if not provided
            if not key:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                key = f"gpg-reports/gpg_usage_report_{timestamp}.{report_file.split('.')[-1]}"
            
            # Upload file
            s3_client.upload_file(report_file, bucket, key)
            
            print(f"Report uploaded to s3://{bucket}/{key}")
            return True
            
        except Exception as e:
            print(f"Error uploading to S3: {e}")
            return False
    
    def scp_to_remote(self, report_file: str, remote_host: str, remote_path: str,
                     username: Optional[str] = None, password: Optional[str] = None,
                     key_file: Optional[str] = None) -> bool:
        """Upload report to remote server via SCP"""
        try:
            # SSH configuration
            ssh_username = username or os.getenv('SSH_USERNAME')
            ssh_password = password or os.getenv('SSH_PASSWORD')
            ssh_key_file = key_file or os.getenv('SSH_KEY_FILE')
            
            # Create SSH client
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to remote host
            if ssh_key_file:
                ssh_client.connect(
                    remote_host,
                    username=ssh_username,
                    key_filename=ssh_key_file
                )
            else:
                ssh_client.connect(
                    remote_host,
                    username=ssh_username,
                    password=ssh_password
                )
            
            # Create SFTP client and upload file
            sftp_client = ssh_client.open_sftp()
            remote_file = os.path.join(remote_path, os.path.basename(report_file))
            sftp_client.put(report_file, remote_file)
            
            sftp_client.close()
            ssh_client.close()
            
            print(f"Report uploaded to {remote_host}:{remote_file}")
            return True
            
        except Exception as e:
            print(f"Error uploading via SCP: {e}")
            return False
