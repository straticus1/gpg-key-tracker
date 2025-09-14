#!/usr/bin/env python3
"""
CLI utility for GPG Key Server management
Provides commands for API key and master key management
"""

import argparse
import sys
import json
import getpass
from datetime import datetime
from typing import Optional, List, Dict, Any
import logging

import sys
import os
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)
sys.path.append(os.path.join(parent_dir, 'lib'))

from api_key_manager import APIKeyManager, create_default_permissions
from master_key_manager import MasterKeyManager
from lib.config import get_config, Config
from lib.models import create_database

# Setup logging for CLI
logging.basicConfig(
    level=logging.WARNING,  # Only show warnings and errors in CLI
    format='%(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)


class ServerCLI:
    """GPG Key Server CLI management utility"""

    def __init__(self):
        self.config = get_config()
        self.api_key_manager = APIKeyManager()
        self.master_key_manager = MasterKeyManager()

    def create_api_key(self, name: str, owner: str, operations: List[str],
                      keys: str = "*", rate_limit: int = 100,
                      expires_days: Optional[int] = None, notes: Optional[str] = None) -> bool:
        """Create a new API key"""
        try:
            # Create permissions structure
            permissions = create_default_permissions(operations, keys)

            # Create API key
            result = self.api_key_manager.create_api_key(
                name=name,
                owner=owner,
                permissions=permissions,
                expires_days=expires_days,
                rate_limit=rate_limit,
                notes=notes
            )

            print(f"✅ API Key created successfully!")
            print(f"ID: {result['id']}")
            print(f"Name: {result['name']}")
            print(f"Owner: {result['owner']}")
            print(f"API Key: {result['api_key']}")
            print(f"⚠️  Save this API key securely - it won't be shown again!")

            if result['expires_at']:
                print(f"Expires: {result['expires_at']}")

            return True

        except Exception as e:
            print(f"❌ Failed to create API key: {e}")
            return False

    def list_api_keys(self, owner: Optional[str] = None, include_inactive: bool = False) -> bool:
        """List API keys"""
        try:
            api_keys = self.api_key_manager.list_api_keys(owner=owner, include_inactive=include_inactive)

            if not api_keys:
                print("No API keys found.")
                return True

            print(f"\n📋 API Keys ({len(api_keys)} found):")
            print("-" * 100)
            print(f"{'ID':<5} {'Name':<20} {'Owner':<15} {'Created':<12} {'Status':<8} {'Rate Limit':<10}")
            print("-" * 100)

            for key in api_keys:
                status = "Active" if key['is_active'] else "Inactive"
                created = key['created_at'].strftime("%Y-%m-%d") if key['created_at'] else "Unknown"

                print(f"{key['id']:<5} {key['name'][:19]:<20} {key['owner'][:14]:<15} "
                      f"{created:<12} {status:<8} {key['rate_limit']:<10}")

            return True

        except Exception as e:
            print(f"❌ Failed to list API keys: {e}")
            return False

    def show_api_key(self, key_id: int) -> bool:
        """Show detailed API key information"""
        try:
            api_key = self.api_key_manager.get_api_key(key_id)

            if not api_key:
                print(f"❌ API key {key_id} not found.")
                return False

            print(f"\n🔑 API Key Details (ID: {key_id}):")
            print("-" * 50)
            print(f"Name: {api_key['name']}")
            print(f"Owner: {api_key['owner']}")
            print(f"Status: {'Active' if api_key['is_active'] else 'Inactive'}")
            print(f"Created: {api_key['created_at']}")
            print(f"Rate Limit: {api_key['rate_limit']} req/min")

            if api_key['expires_at']:
                print(f"Expires: {api_key['expires_at']}")
            else:
                print("Expires: Never")

            if api_key['last_used_at']:
                print(f"Last Used: {api_key['last_used_at']}")
            else:
                print("Last Used: Never")

            if api_key['notes']:
                print(f"Notes: {api_key['notes']}")

            # Show permissions
            permissions = api_key['permissions']
            print(f"\nPermissions:")
            print(f"  Operations: {', '.join(permissions.get('operations', []))}")
            print(f"  Keys: {permissions.get('keys', 'None')}")

            return True

        except Exception as e:
            print(f"❌ Failed to show API key: {e}")
            return False

    def update_api_key(self, key_id: int, **kwargs) -> bool:
        """Update API key"""
        try:
            # Filter out None values
            update_data = {k: v for k, v in kwargs.items() if v is not None}

            if not update_data:
                print("❌ No updates specified.")
                return False

            success = self.api_key_manager.update_api_key(key_id, **update_data)

            if success:
                print(f"✅ API key {key_id} updated successfully!")
                return True
            else:
                print(f"❌ Failed to update API key {key_id} (not found or no changes).")
                return False

        except Exception as e:
            print(f"❌ Failed to update API key: {e}")
            return False

    def delete_api_key(self, key_id: int, hard_delete: bool = False) -> bool:
        """Delete API key"""
        try:
            # Confirm deletion
            api_key = self.api_key_manager.get_api_key(key_id)
            if not api_key:
                print(f"❌ API key {key_id} not found.")
                return False

            action = "permanently delete" if hard_delete else "deactivate"
            confirm = input(f"⚠️  Are you sure you want to {action} API key '{api_key['name']}'? (y/N): ")

            if confirm.lower() != 'y':
                print("Cancelled.")
                return False

            success = self.api_key_manager.delete_api_key(key_id, soft_delete=not hard_delete)

            if success:
                print(f"✅ API key {key_id} {'deleted' if hard_delete else 'deactivated'} successfully!")
                return True
            else:
                print(f"❌ Failed to delete API key {key_id}.")
                return False

        except Exception as e:
            print(f"❌ Failed to delete API key: {e}")
            return False

    def rotate_api_key(self, key_id: int) -> bool:
        """Rotate API key"""
        try:
            new_key = self.api_key_manager.rotate_api_key(key_id)

            if new_key:
                print(f"✅ API key {key_id} rotated successfully!")
                print(f"New API Key: {new_key}")
                print(f"⚠️  Save this API key securely - it won't be shown again!")
                return True
            else:
                print(f"❌ Failed to rotate API key {key_id}.")
                return False

        except Exception as e:
            print(f"❌ Failed to rotate API key: {e}")
            return False

    def create_master_key(self, name: str, key_type: str, key_role: str = "master",
                         organization: Optional[str] = None, email: Optional[str] = None,
                         key_size: int = 4096, set_as_default: bool = False) -> bool:
        """Create master key"""
        try:
            result = self.master_key_manager.create_master_key(
                name=name,
                key_type=key_type,
                key_role=key_role,
                organization=organization,
                email=email,
                key_size=key_size,
                set_as_default=set_as_default
            )

            print(f"✅ Master {key_type} key created successfully!")
            print(f"ID: {result['id']}")
            print(f"Name: {result['name']}")
            print(f"Fingerprint: {result['fingerprint']}")
            print(f"Type: {result['key_type']}")
            print(f"Role: {result['key_role']}")

            if result['organization']:
                print(f"Organization: {result['organization']}")

            if result['is_default']:
                print(f"✨ Set as default {key_type} key")

            return True

        except Exception as e:
            print(f"❌ Failed to create master key: {e}")
            return False

    def create_organizational_keys(self, organization: str, name: str,
                                  email: Optional[str] = None, key_size: int = 4096) -> bool:
        """Create organizational key pair"""
        try:
            result = self.master_key_manager.create_organizational_key_pair(
                organization=organization,
                name=name,
                email=email,
                key_size=key_size
            )

            print(f"✅ Organizational key pair created successfully!")
            print(f"Organization: {result['organization']}")
            print(f"\n🔐 Signing Key:")
            print(f"  ID: {result['signing_key']['id']}")
            print(f"  Fingerprint: {result['signing_key']['fingerprint']}")
            print(f"  Default: {result['signing_key']['is_default']}")

            print(f"\n🔒 Encryption Key:")
            print(f"  ID: {result['encryption_key']['id']}")
            print(f"  Fingerprint: {result['encryption_key']['fingerprint']}")
            print(f"  Default: {result['encryption_key']['is_default']}")

            return True

        except Exception as e:
            print(f"❌ Failed to create organizational keys: {e}")
            return False

    def list_master_keys(self, key_type: Optional[str] = None, key_role: Optional[str] = None) -> bool:
        """List master keys"""
        try:
            master_keys = self.master_key_manager.list_master_keys(
                key_type=key_type,
                key_role=key_role,
                include_inactive=True
            )

            if not master_keys:
                print("No master keys found.")
                return True

            print(f"\n🔐 Master Keys ({len(master_keys)} found):")
            print("-" * 120)
            print(f"{'ID':<5} {'Name':<25} {'Type':<12} {'Role':<15} {'Fingerprint':<20} {'Default':<8} {'Status':<8}")
            print("-" * 120)

            for key in master_keys:
                status = "Active" if key['is_active'] else "Inactive"
                default = "Yes" if key['is_default'] else "No"
                fingerprint = key['fingerprint'][:16] + "..." if len(key['fingerprint']) > 16 else key['fingerprint']

                print(f"{key['id']:<5} {key['name'][:24]:<25} {key['key_type']:<12} "
                      f"{key['key_role']:<15} {fingerprint:<20} {default:<8} {status:<8}")

            return True

        except Exception as e:
            print(f"❌ Failed to list master keys: {e}")
            return False

    def backup_master_keys(self, backup_path: str) -> bool:
        """Backup master keys"""
        try:
            success = self.master_key_manager.backup_master_keys(backup_path)

            if success:
                print(f"✅ Master keys backed up to: {backup_path}")
                return True
            else:
                print(f"❌ Failed to backup master keys.")
                return False

        except Exception as e:
            print(f"❌ Failed to backup master keys: {e}")
            return False

    def get_usage_stats(self, days: int = 30, api_key_id: Optional[int] = None) -> bool:
        """Get API usage statistics"""
        try:
            stats = self.api_key_manager.get_api_usage_stats(api_key_id=api_key_id, days=days)

            if not stats:
                print("No usage statistics available.")
                return True

            print(f"\n📊 API Usage Statistics (Last {days} days):")
            print("-" * 50)
            print(f"Total Requests: {stats['total_requests']}")
            print(f"Successful Requests: {stats['successful_requests']}")
            print(f"Error Requests: {stats['error_requests']}")
            print(f"Success Rate: {stats['success_rate']:.1f}%")

            # Show endpoint stats
            if stats['endpoint_stats']:
                print(f"\n📍 Top Endpoints:")
                for endpoint, endpoint_stats in sorted(
                    stats['endpoint_stats'].items(),
                    key=lambda x: x[1]['count'],
                    reverse=True
                )[:10]:
                    print(f"  {endpoint}: {endpoint_stats['count']} requests, "
                          f"{endpoint_stats['errors']} errors")

            # Show API key stats
            if stats['api_key_stats'] and not api_key_id:
                print(f"\n🔑 Top API Keys:")
                for key_id, key_stats in sorted(
                    stats['api_key_stats'].items(),
                    key=lambda x: x[1]['count'],
                    reverse=True
                )[:10]:
                    print(f"  Key {key_id}: {key_stats['count']} requests, "
                          f"{key_stats['errors']} errors")

            return True

        except Exception as e:
            print(f"❌ Failed to get usage statistics: {e}")
            return False


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="GPG Key Server CLI Management Utility",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # API Key management
    api_parser = subparsers.add_parser('api-key', help='API key management')
    api_subparsers = api_parser.add_subparsers(dest='api_action')

    # Create API key
    create_api = api_subparsers.add_parser('create', help='Create new API key')
    create_api.add_argument('--name', required=True, help='API key name')
    create_api.add_argument('--owner', required=True, help='Key owner')
    create_api.add_argument('--operations', required=True, nargs='+',
                           choices=['read', 'list', 'sign', 'encrypt', 'info', 'search', 'admin'],
                           help='Allowed operations')
    create_api.add_argument('--keys', default='*', help='Allowed key fingerprints (* for all)')
    create_api.add_argument('--rate-limit', type=int, default=100, help='Rate limit per minute')
    create_api.add_argument('--expires-days', type=int, help='Expiration in days')
    create_api.add_argument('--notes', help='Optional notes')

    # List API keys
    list_api = api_subparsers.add_parser('list', help='List API keys')
    list_api.add_argument('--owner', help='Filter by owner')
    list_api.add_argument('--include-inactive', action='store_true', help='Include inactive keys')

    # Show API key
    show_api = api_subparsers.add_parser('show', help='Show API key details')
    show_api.add_argument('id', type=int, help='API key ID')

    # Update API key
    update_api = api_subparsers.add_parser('update', help='Update API key')
    update_api.add_argument('id', type=int, help='API key ID')
    update_api.add_argument('--name', help='New name')
    update_api.add_argument('--rate-limit', type=int, help='New rate limit')
    update_api.add_argument('--notes', help='New notes')
    update_api.add_argument('--activate', action='store_true', help='Activate key')
    update_api.add_argument('--deactivate', action='store_true', help='Deactivate key')

    # Delete API key
    delete_api = api_subparsers.add_parser('delete', help='Delete API key')
    delete_api.add_argument('id', type=int, help='API key ID')
    delete_api.add_argument('--hard', action='store_true', help='Permanent deletion')

    # Rotate API key
    rotate_api = api_subparsers.add_parser('rotate', help='Rotate API key')
    rotate_api.add_argument('id', type=int, help='API key ID')

    # Master Key management
    master_parser = subparsers.add_parser('master-key', help='Master key management')
    master_subparsers = master_parser.add_subparsers(dest='master_action')

    # Create master key
    create_master = master_subparsers.add_parser('create', help='Create master key')
    create_master.add_argument('--name', required=True, help='Key name')
    create_master.add_argument('--type', required=True, choices=['signing', 'encryption'], help='Key type')
    create_master.add_argument('--role', default='master', choices=['master', 'organizational'], help='Key role')
    create_master.add_argument('--organization', help='Organization name')
    create_master.add_argument('--email', help='Contact email')
    create_master.add_argument('--key-size', type=int, default=4096, help='Key size in bits')
    create_master.add_argument('--set-default', action='store_true', help='Set as default key')

    # Create organizational keys
    create_org = master_subparsers.add_parser('create-organizational', help='Create organizational key pair')
    create_org.add_argument('--organization', required=True, help='Organization name')
    create_org.add_argument('--name', required=True, help='Key name')
    create_org.add_argument('--email', help='Contact email')
    create_org.add_argument('--key-size', type=int, default=4096, help='Key size in bits')

    # List master keys
    list_master = master_subparsers.add_parser('list', help='List master keys')
    list_master.add_argument('--type', choices=['signing', 'encryption'], help='Filter by type')
    list_master.add_argument('--role', choices=['master', 'organizational'], help='Filter by role')

    # Backup master keys
    backup_master = master_subparsers.add_parser('backup', help='Backup master keys')
    backup_master.add_argument('path', help='Backup directory path')

    # Usage statistics
    stats_parser = subparsers.add_parser('stats', help='API usage statistics')
    stats_parser.add_argument('--days', type=int, default=30, help='Number of days')
    stats_parser.add_argument('--api-key-id', type=int, help='Specific API key ID')

    # Initialize database
    init_parser = subparsers.add_parser('init', help='Initialize database')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    cli = ServerCLI()

    try:
        # Handle commands
        if args.command == 'init':
            print("🔧 Initializing database...")
            create_database()
            print("✅ Database initialized successfully!")
            return 0

        elif args.command == 'api-key':
            if args.api_action == 'create':
                keys = args.keys.split(',') if args.keys != '*' else '*'
                success = cli.create_api_key(
                    name=args.name,
                    owner=args.owner,
                    operations=args.operations,
                    keys=keys,
                    rate_limit=args.rate_limit,
                    expires_days=args.expires_days,
                    notes=args.notes
                )

            elif args.api_action == 'list':
                success = cli.list_api_keys(
                    owner=args.owner,
                    include_inactive=args.include_inactive
                )

            elif args.api_action == 'show':
                success = cli.show_api_key(args.id)

            elif args.api_action == 'update':
                update_data = {}
                if args.name:
                    update_data['name'] = args.name
                if args.rate_limit:
                    update_data['rate_limit'] = args.rate_limit
                if args.notes:
                    update_data['notes'] = args.notes
                if args.activate:
                    update_data['is_active'] = True
                if args.deactivate:
                    update_data['is_active'] = False

                success = cli.update_api_key(args.id, **update_data)

            elif args.api_action == 'delete':
                success = cli.delete_api_key(args.id, hard_delete=args.hard)

            elif args.api_action == 'rotate':
                success = cli.rotate_api_key(args.id)

            else:
                api_parser.print_help()
                return 1

        elif args.command == 'master-key':
            if args.master_action == 'create':
                success = cli.create_master_key(
                    name=args.name,
                    key_type=args.type,
                    key_role=args.role,
                    organization=args.organization,
                    email=args.email,
                    key_size=args.key_size,
                    set_as_default=args.set_default
                )

            elif args.master_action == 'create-organizational':
                success = cli.create_organizational_keys(
                    organization=args.organization,
                    name=args.name,
                    email=args.email,
                    key_size=args.key_size
                )

            elif args.master_action == 'list':
                success = cli.list_master_keys(
                    key_type=args.type,
                    key_role=args.role
                )

            elif args.master_action == 'backup':
                success = cli.backup_master_keys(args.path)

            else:
                master_parser.print_help()
                return 1

        elif args.command == 'stats':
            success = cli.get_usage_stats(
                days=args.days,
                api_key_id=args.api_key_id
            )

        else:
            parser.print_help()
            return 1

        return 0 if success else 1

    except KeyboardInterrupt:
        print("\n❌ Cancelled by user.")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        logger.exception("Unexpected error in CLI")
        return 1


if __name__ == '__main__':
    sys.exit(main())