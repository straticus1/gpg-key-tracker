#!/usr/bin/env python3
"""
Backup and Restore functionality for GPG Key Tracker
"""

import os
import json
import gzip
import shutil
import logging
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import sqlite3
from contextlib import contextmanager
from sqlalchemy import create_engine, text
from gpg_manager import GPGManager
from models import GPGKey, UsageLog, get_database_url, get_session
from config import get_config

logger = logging.getLogger(__name__)


class BackupManager:
    """Manages backup and restore operations for GPG Key Tracker"""

    def __init__(self, config=None):
        """Initialize backup manager"""
        self.config = config or get_config()
        self.gpg_manager = GPGManager(config=self.config)
        self.backup_dir = Path(self.config.backup.path)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create_full_backup(self, backup_name: Optional[str] = None) -> Dict[str, Any]:
        """Create a full backup including database and GPG keyring"""
        if backup_name is None:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            backup_name = f"gpg_tracker_backup_{timestamp}"

        backup_path = self.backup_dir / backup_name
        backup_path.mkdir(parents=True, exist_ok=True)

        try:
            backup_info = {
                'backup_name': backup_name,
                'timestamp': datetime.utcnow().isoformat(),
                'version': '1.2.0',  # TODO: Get from setup.py
                'components': {}
            }

            # Backup database
            db_backup_path = backup_path / 'database.db'
            if self._backup_database(db_backup_path):
                backup_info['components']['database'] = {
                    'path': str(db_backup_path),
                    'size': db_backup_path.stat().st_size,
                    'status': 'success'
                }
            else:
                backup_info['components']['database'] = {'status': 'failed'}

            # Backup GPG keyring
            gpg_backup_path = backup_path / 'gpg_keyring'
            if self._backup_gpg_keyring(gpg_backup_path):
                backup_info['components']['gpg_keyring'] = {
                    'path': str(gpg_backup_path),
                    'status': 'success'
                }
            else:
                backup_info['components']['gpg_keyring'] = {'status': 'failed'}

            # Export key metadata as JSON for additional safety
            metadata_path = backup_path / 'key_metadata.json'
            if self._export_key_metadata(metadata_path):
                backup_info['components']['metadata'] = {
                    'path': str(metadata_path),
                    'size': metadata_path.stat().st_size,
                    'status': 'success'
                }
            else:
                backup_info['components']['metadata'] = {'status': 'failed'}

            # Export usage logs
            logs_path = backup_path / 'usage_logs.json'
            if self._export_usage_logs(logs_path):
                backup_info['components']['usage_logs'] = {
                    'path': str(logs_path),
                    'size': logs_path.stat().st_size,
                    'status': 'success'
                }
            else:
                backup_info['components']['usage_logs'] = {'status': 'failed'}

            # Save backup info
            info_path = backup_path / 'backup_info.json'
            with open(info_path, 'w') as f:
                json.dump(backup_info, f, indent=2)

            # Compress backup if configured
            if self.config.backup.compress:
                compressed_path = self._compress_backup(backup_path)
                if compressed_path:
                    # Remove uncompressed directory
                    shutil.rmtree(backup_path)
                    backup_info['compressed_path'] = str(compressed_path)
                    backup_info['compressed_size'] = compressed_path.stat().st_size

            logger.info(f"Full backup created successfully: {backup_name}")
            return backup_info

        except Exception as e:
            logger.error(f"Failed to create full backup: {e}")
            # Clean up partial backup
            if backup_path.exists():
                shutil.rmtree(backup_path)
            raise

    def _backup_database(self, backup_path: Path) -> bool:
        """Backup SQLite database"""
        try:
            db_url = get_database_url()
            if not db_url.startswith('sqlite:///'):
                logger.error("Only SQLite databases are supported for backup")
                return False

            db_file = db_url.replace('sqlite:///', '')
            if not os.path.exists(db_file):
                logger.error(f"Database file not found: {db_file}")
                return False

            # Use SQLite backup API for consistent backup
            with sqlite3.connect(db_file) as source:
                with sqlite3.connect(str(backup_path)) as backup:
                    source.backup(backup)

            logger.info(f"Database backed up to {backup_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to backup database: {e}")
            return False

    def _backup_gpg_keyring(self, backup_path: Path) -> bool:
        """Backup GPG keyring directory"""
        try:
            gpg_home = Path(self.config.gpg.home)
            if not gpg_home.exists():
                logger.warning(f"GPG home directory not found: {gpg_home}")
                return False

            backup_path.mkdir(parents=True, exist_ok=True)

            # Copy essential GPG files
            essential_files = [
                'pubring.gpg', 'secring.gpg',  # Legacy format
                'pubring.kbx', 'trustdb.gpg',  # Modern format
                'gpg.conf', 'gpg-agent.conf'
            ]

            copied_files = []
            for filename in essential_files:
                src_file = gpg_home / filename
                if src_file.exists():
                    dst_file = backup_path / filename
                    shutil.copy2(src_file, dst_file)
                    copied_files.append(filename)

            # Copy private-keys-v1.d directory if it exists
            private_keys_dir = gpg_home / 'private-keys-v1.d'
            if private_keys_dir.exists():
                dst_private_keys = backup_path / 'private-keys-v1.d'
                shutil.copytree(private_keys_dir, dst_private_keys)
                copied_files.append('private-keys-v1.d/')

            logger.info(f"GPG keyring backed up to {backup_path}. Files: {copied_files}")
            return len(copied_files) > 0

        except Exception as e:
            logger.error(f"Failed to backup GPG keyring: {e}")
            return False

    def _export_key_metadata(self, export_path: Path) -> bool:
        """Export key metadata to JSON"""
        try:
            keys = self.gpg_manager.list_keys(include_inactive=True)
            key_metadata = {
                'export_timestamp': datetime.utcnow().isoformat(),
                'total_keys': len(keys),
                'keys': keys
            }

            with open(export_path, 'w') as f:
                json.dump(key_metadata, f, indent=2, default=str)

            logger.info(f"Key metadata exported to {export_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export key metadata: {e}")
            return False

    def _export_usage_logs(self, export_path: Path) -> bool:
        """Export usage logs to JSON"""
        try:
            logs = self.gpg_manager.get_usage_logs(limit=10000)  # Large limit for backup
            log_data = {
                'export_timestamp': datetime.utcnow().isoformat(),
                'total_logs': len(logs),
                'logs': logs
            }

            with open(export_path, 'w') as f:
                json.dump(log_data, f, indent=2, default=str)

            logger.info(f"Usage logs exported to {export_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export usage logs: {e}")
            return False

    def _compress_backup(self, backup_path: Path) -> Optional[Path]:
        """Compress backup directory to gzipped tar"""
        try:
            compressed_path = backup_path.with_suffix('.tar.gz')
            shutil.make_archive(
                str(backup_path),
                'gztar',
                root_dir=backup_path.parent,
                base_dir=backup_path.name
            )
            logger.info(f"Backup compressed to {compressed_path}")
            return compressed_path

        except Exception as e:
            logger.error(f"Failed to compress backup: {e}")
            return None

    def restore_from_backup(self, backup_name: str, components: Optional[List[str]] = None) -> Dict[str, Any]:
        """Restore from a backup"""
        if components is None:
            components = ['database', 'gpg_keyring', 'metadata', 'usage_logs']

        # Find backup
        backup_path = self.backup_dir / backup_name
        compressed_backup = self.backup_dir / f"{backup_name}.tar.gz"

        if compressed_backup.exists():
            # Extract compressed backup
            backup_path = self._extract_backup(compressed_backup)
            if not backup_path:
                raise ValueError(f"Failed to extract backup: {backup_name}")
        elif not backup_path.exists():
            raise ValueError(f"Backup not found: {backup_name}")

        try:
            # Load backup info
            info_path = backup_path / 'backup_info.json'
            if not info_path.exists():
                raise ValueError("Backup info not found. Invalid backup.")

            with open(info_path, 'r') as f:
                backup_info = json.load(f)

            restore_results = {
                'backup_name': backup_name,
                'restore_timestamp': datetime.utcnow().isoformat(),
                'components': {}
            }

            # Restore database
            if 'database' in components and 'database' in backup_info['components']:
                db_backup_path = backup_path / 'database.db'
                if self._restore_database(db_backup_path):
                    restore_results['components']['database'] = {'status': 'success'}
                else:
                    restore_results['components']['database'] = {'status': 'failed'}

            # Restore GPG keyring
            if 'gpg_keyring' in components and 'gpg_keyring' in backup_info['components']:
                gpg_backup_path = backup_path / 'gpg_keyring'
                if self._restore_gpg_keyring(gpg_backup_path):
                    restore_results['components']['gpg_keyring'] = {'status': 'success'}
                else:
                    restore_results['components']['gpg_keyring'] = {'status': 'failed'}

            logger.info(f"Restore completed from backup: {backup_name}")
            return restore_results

        except Exception as e:
            logger.error(f"Failed to restore from backup: {e}")
            raise
        finally:
            # Clean up extracted backup if it was compressed
            if compressed_backup.exists() and backup_path.exists():
                shutil.rmtree(backup_path)

    def _extract_backup(self, compressed_path: Path) -> Optional[Path]:
        """Extract compressed backup"""
        try:
            extract_dir = compressed_path.parent / f"temp_extract_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            shutil.unpack_archive(str(compressed_path), str(extract_dir))

            # Find the backup directory inside
            extracted_contents = list(extract_dir.iterdir())
            if len(extracted_contents) == 1 and extracted_contents[0].is_dir():
                return extracted_contents[0]
            else:
                return extract_dir

        except Exception as e:
            logger.error(f"Failed to extract backup: {e}")
            return None

    def _restore_database(self, backup_db_path: Path) -> bool:
        """Restore database from backup"""
        try:
            if not backup_db_path.exists():
                logger.error(f"Database backup not found: {backup_db_path}")
                return False

            db_url = get_database_url()
            current_db_file = db_url.replace('sqlite:///', '')

            # Create backup of current database
            if os.path.exists(current_db_file):
                backup_current = f"{current_db_file}.pre_restore_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(current_db_file, backup_current)
                logger.info(f"Current database backed up to {backup_current}")

            # Restore from backup
            shutil.copy2(backup_db_path, current_db_file)
            logger.info(f"Database restored from {backup_db_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to restore database: {e}")
            return False

    def _restore_gpg_keyring(self, backup_keyring_path: Path) -> bool:
        """Restore GPG keyring from backup"""
        try:
            if not backup_keyring_path.exists():
                logger.error(f"GPG keyring backup not found: {backup_keyring_path}")
                return False

            gpg_home = Path(self.config.gpg.home)

            # Create backup of current keyring
            if gpg_home.exists():
                backup_current = gpg_home.parent / f"{gpg_home.name}.pre_restore_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
                shutil.copytree(gpg_home, backup_current)
                logger.info(f"Current GPG keyring backed up to {backup_current}")

            # Restore from backup
            if gpg_home.exists():
                shutil.rmtree(gpg_home)
            shutil.copytree(backup_keyring_path, gpg_home)

            # Set proper permissions
            os.chmod(gpg_home, 0o700)
            for root, dirs, files in os.walk(gpg_home):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o700)
                for f in files:
                    os.chmod(os.path.join(root, f), 0o600)

            logger.info(f"GPG keyring restored from {backup_keyring_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to restore GPG keyring: {e}")
            return False

    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backups"""
        backups = []

        try:
            for item in self.backup_dir.iterdir():
                backup_info = {'name': item.name}

                if item.is_dir():
                    info_path = item / 'backup_info.json'
                    if info_path.exists():
                        with open(info_path, 'r') as f:
                            backup_data = json.load(f)
                            backup_info.update(backup_data)
                    backup_info['type'] = 'directory'
                    backup_info['size'] = sum(f.stat().st_size for f in item.rglob('*') if f.is_file())

                elif item.suffix == '.gz' and item.name.endswith('.tar.gz'):
                    backup_info['type'] = 'compressed'
                    backup_info['size'] = item.stat().st_size

                backup_info['created'] = datetime.fromtimestamp(item.stat().st_mtime)
                backups.append(backup_info)

        except Exception as e:
            logger.error(f"Failed to list backups: {e}")

        return sorted(backups, key=lambda x: x.get('created', datetime.min), reverse=True)

    def delete_backup(self, backup_name: str) -> bool:
        """Delete a backup"""
        try:
            backup_path = self.backup_dir / backup_name
            compressed_backup = self.backup_dir / f"{backup_name}.tar.gz"

            if backup_path.exists() and backup_path.is_dir():
                shutil.rmtree(backup_path)
                logger.info(f"Deleted backup directory: {backup_name}")
                return True
            elif compressed_backup.exists():
                compressed_backup.unlink()
                logger.info(f"Deleted compressed backup: {backup_name}.tar.gz")
                return True
            else:
                logger.warning(f"Backup not found: {backup_name}")
                return False

        except Exception as e:
            logger.error(f"Failed to delete backup {backup_name}: {e}")
            return False

    def cleanup_old_backups(self, keep_days: Optional[int] = None) -> int:
        """Clean up old backups based on retention policy"""
        if keep_days is None:
            keep_days = self.config.backup.retention_days

        cutoff_date = datetime.utcnow() - timedelta(days=keep_days)
        deleted_count = 0

        try:
            backups = self.list_backups()
            for backup in backups:
                if backup.get('created', datetime.max) < cutoff_date:
                    if self.delete_backup(backup['name']):
                        deleted_count += 1

            logger.info(f"Cleaned up {deleted_count} old backups")
            return deleted_count

        except Exception as e:
            logger.error(f"Failed to cleanup old backups: {e}")
            return 0


# Utility functions for scheduled backups
def create_scheduled_backup():
    """Create a scheduled backup (for use with cron/systemd)"""
    try:
        backup_manager = BackupManager()
        backup_info = backup_manager.create_full_backup()
        print(f"Backup created successfully: {backup_info['backup_name']}")

        # Cleanup old backups
        deleted = backup_manager.cleanup_old_backups()
        if deleted > 0:
            print(f"Cleaned up {deleted} old backups")

    except Exception as e:
        print(f"Scheduled backup failed: {e}")
        exit(1)


if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == 'scheduled':
        create_scheduled_backup()
    else:
        # Test backup functionality
        backup_manager = BackupManager()
        print("Testing backup functionality...")

        try:
            backup_info = backup_manager.create_full_backup('test_backup')
            print(f"Test backup created: {backup_info}")

            backups = backup_manager.list_backups()
            print(f"Available backups: {len(backups)}")

        except Exception as e:
            print(f"Test failed: {e}")