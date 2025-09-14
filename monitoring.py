#!/usr/bin/env python3
"""
Monitoring and metrics collection for GPG Key Tracker
"""

import os
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import json
import threading
from contextlib import contextmanager

try:
    from prometheus_client import Counter as PrometheusCounter, Histogram, Gauge, CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST
    from prometheus_client.exposition import start_http_server
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logging.warning("Prometheus client not available. Metrics will be logged only.")

from config import get_config
from models import GPGKey, UsageLog, get_session
from sqlalchemy import func

logger = logging.getLogger(__name__)


@dataclass
class HealthStatus:
    """Health check status"""
    service: str
    status: str  # healthy, degraded, unhealthy
    timestamp: datetime
    details: Dict[str, Any]
    response_time_ms: Optional[float] = None


@dataclass
class Metrics:
    """System metrics snapshot"""
    timestamp: datetime
    total_keys: int
    active_keys: int
    expired_keys: int
    expiring_keys: int  # Within 30 days
    total_operations: int
    successful_operations: int
    failed_operations: int
    success_rate: float
    operations_by_type: Dict[str, int]
    operations_by_user: Dict[str, int]
    avg_response_time_ms: Optional[float] = None
    database_size_mb: Optional[float] = None


class MetricsCollector:
    """Collects and manages application metrics"""

    def __init__(self, config=None):
        """Initialize metrics collector"""
        self.config = config or get_config()
        self.start_time = time.time()

        # Thread-safe counters for real-time metrics
        self._lock = threading.RLock()
        self._operation_counts = defaultdict(int)
        self._success_counts = defaultdict(int)
        self._response_times = []

        # Prometheus metrics (if available)
        self.registry = None
        self.prometheus_metrics = {}

        if PROMETHEUS_AVAILABLE and self.config.monitoring.enabled:
            self._setup_prometheus_metrics()

    def _setup_prometheus_metrics(self):
        """Setup Prometheus metrics"""
        try:
            self.registry = CollectorRegistry()

            # Counter metrics
            self.prometheus_metrics['operations_total'] = PrometheusCounter(
                'gpg_operations_total',
                'Total number of GPG operations',
                ['operation', 'status'],
                registry=self.registry
            )

            self.prometheus_metrics['keys_total'] = Gauge(
                'gpg_keys_total',
                'Total number of GPG keys',
                ['status', 'expired'],
                registry=self.registry
            )

            # Histogram for response times
            self.prometheus_metrics['operation_duration'] = Histogram(
                'gpg_operation_duration_seconds',
                'Duration of GPG operations',
                ['operation'],
                registry=self.registry
            )

            # Database metrics
            self.prometheus_metrics['database_size'] = Gauge(
                'gpg_database_size_bytes',
                'Size of the GPG database',
                registry=self.registry
            )

            self.prometheus_metrics['database_connections'] = Gauge(
                'gpg_database_connections',
                'Number of active database connections',
                registry=self.registry
            )

            logger.info("Prometheus metrics initialized")

        except Exception as e:
            logger.error(f"Failed to setup Prometheus metrics: {e}")
            self.prometheus_metrics = {}

    @contextmanager
    def operation_timer(self, operation: str):
        """Context manager to time operations"""
        start_time = time.time()
        success = False

        try:
            yield
            success = True
        except Exception:
            success = False
            raise
        finally:
            duration = time.time() - start_time
            self.record_operation(operation, success, duration)

    def record_operation(self, operation: str, success: bool, duration_seconds: Optional[float] = None):
        """Record an operation metric"""
        with self._lock:
            self._operation_counts[operation] += 1
            if success:
                self._success_counts[operation] += 1

            if duration_seconds is not None:
                self._response_times.append(duration_seconds * 1000)  # Store in ms
                # Keep only last 1000 response times to prevent memory leak
                if len(self._response_times) > 1000:
                    self._response_times = self._response_times[-1000:]

        # Update Prometheus metrics
        if self.prometheus_metrics:
            try:
                status = 'success' if success else 'failure'
                self.prometheus_metrics['operations_total'].labels(operation=operation, status=status).inc()

                if duration_seconds is not None:
                    self.prometheus_metrics['operation_duration'].labels(operation=operation).observe(duration_seconds)

            except Exception as e:
                logger.warning(f"Failed to update Prometheus metrics: {e}")

    def get_current_metrics(self) -> Metrics:
        """Get current system metrics"""
        try:
            with get_session() as session:
                # Key counts
                total_keys = session.query(GPGKey).count()
                active_keys = session.query(GPGKey).filter(GPGKey.is_active == True).count()
                expired_keys = session.query(GPGKey).filter(
                    GPGKey.is_active == True,
                    GPGKey.is_expired == True
                ).count()

                # Expiring keys (within 30 days)
                future_date = datetime.utcnow() + timedelta(days=30)
                expiring_keys = session.query(GPGKey).filter(
                    GPGKey.is_active == True,
                    GPGKey.expires_at != None,
                    GPGKey.expires_at <= future_date,
                    GPGKey.expires_at > datetime.utcnow()
                ).count()

                # Operation counts
                total_operations = session.query(UsageLog).count()
                successful_operations = session.query(UsageLog).filter(UsageLog.success == True).count()
                failed_operations = total_operations - successful_operations

                success_rate = (successful_operations / total_operations * 100) if total_operations > 0 else 0.0

                # Operations by type (last 24 hours)
                yesterday = datetime.utcnow() - timedelta(days=1)
                operations_by_type = {}

                type_counts = session.query(
                    UsageLog.operation,
                    func.count(UsageLog.id)
                ).filter(
                    UsageLog.timestamp >= yesterday
                ).group_by(UsageLog.operation).all()

                for op_type, count in type_counts:
                    operations_by_type[op_type] = count

                # Operations by user (last 24 hours)
                user_counts = session.query(
                    UsageLog.user,
                    func.count(UsageLog.id)
                ).filter(
                    UsageLog.timestamp >= yesterday
                ).group_by(UsageLog.user).all()

                operations_by_user = {}
                for user, count in user_counts:
                    operations_by_user[user] = count

            # Calculate average response time
            avg_response_time = None
            with self._lock:
                if self._response_times:
                    avg_response_time = sum(self._response_times) / len(self._response_times)

            # Get database size
            database_size = self._get_database_size()

            # Update Prometheus gauges
            if self.prometheus_metrics:
                try:
                    self.prometheus_metrics['keys_total'].labels(status='active', expired='false').set(active_keys - expired_keys)
                    self.prometheus_metrics['keys_total'].labels(status='active', expired='true').set(expired_keys)
                    self.prometheus_metrics['keys_total'].labels(status='inactive', expired='false').set(total_keys - active_keys)

                    if database_size:
                        self.prometheus_metrics['database_size'].set(database_size)

                except Exception as e:
                    logger.warning(f"Failed to update Prometheus gauges: {e}")

            return Metrics(
                timestamp=datetime.utcnow(),
                total_keys=total_keys,
                active_keys=active_keys,
                expired_keys=expired_keys,
                expiring_keys=expiring_keys,
                total_operations=total_operations,
                successful_operations=successful_operations,
                failed_operations=failed_operations,
                success_rate=success_rate,
                operations_by_type=operations_by_type,
                operations_by_user=operations_by_user,
                avg_response_time_ms=avg_response_time,
                database_size_mb=database_size / (1024 * 1024) if database_size else None
            )

        except Exception as e:
            logger.error(f"Failed to collect metrics: {e}")
            return Metrics(
                timestamp=datetime.utcnow(),
                total_keys=0, active_keys=0, expired_keys=0, expiring_keys=0,
                total_operations=0, successful_operations=0, failed_operations=0,
                success_rate=0.0, operations_by_type={}, operations_by_user={}
            )

    def _get_database_size(self) -> Optional[float]:
        """Get database file size in bytes"""
        try:
            from models import get_database_url
            db_url = get_database_url()
            if db_url.startswith('sqlite:///'):
                db_file = db_url.replace('sqlite:///', '')
                if os.path.exists(db_file):
                    return float(os.path.getsize(db_file))
            return None
        except Exception as e:
            logger.warning(f"Failed to get database size: {e}")
            return None

    def get_system_uptime(self) -> float:
        """Get system uptime in seconds"""
        return time.time() - self.start_time

    def export_metrics_json(self) -> str:
        """Export current metrics as JSON"""
        metrics = self.get_current_metrics()
        metrics_dict = asdict(metrics)
        metrics_dict['uptime_seconds'] = self.get_system_uptime()
        return json.dumps(metrics_dict, default=str, indent=2)


class HealthChecker:
    """Health checking system"""

    def __init__(self, config=None):
        """Initialize health checker"""
        self.config = config or get_config()

    def check_database_health(self) -> HealthStatus:
        """Check database connectivity and performance"""
        start_time = time.time()

        try:
            with get_session() as session:
                # Simple query to test connectivity
                session.execute('SELECT 1')

                # Check if tables exist
                key_count = session.query(GPGKey).count()
                log_count = session.query(UsageLog).count()

            response_time = (time.time() - start_time) * 1000

            status = "healthy"
            if response_time > 1000:  # > 1 second is concerning
                status = "degraded"

            return HealthStatus(
                service="database",
                status=status,
                timestamp=datetime.utcnow(),
                response_time_ms=response_time,
                details={
                    "total_keys": key_count,
                    "total_logs": log_count,
                    "query_time_ms": response_time
                }
            )

        except Exception as e:
            return HealthStatus(
                service="database",
                status="unhealthy",
                timestamp=datetime.utcnow(),
                response_time_ms=(time.time() - start_time) * 1000,
                details={"error": str(e)}
            )

    def check_gpg_health(self) -> HealthStatus:
        """Check GPG system health"""
        start_time = time.time()

        try:
            import gnupg
            gpg = gnupg.GPG(gnupghome=self.config.gpg.home)

            # Test GPG functionality
            keys = gpg.list_keys()

            response_time = (time.time() - start_time) * 1000

            return HealthStatus(
                service="gpg",
                status="healthy",
                timestamp=datetime.utcnow(),
                response_time_ms=response_time,
                details={
                    "gpg_home": self.config.gpg.home,
                    "total_keys_in_keyring": len(keys),
                    "query_time_ms": response_time
                }
            )

        except Exception as e:
            return HealthStatus(
                service="gpg",
                status="unhealthy",
                timestamp=datetime.utcnow(),
                response_time_ms=(time.time() - start_time) * 1000,
                details={"error": str(e)}
            )

    def check_filesystem_health(self) -> HealthStatus:
        """Check filesystem health"""
        start_time = time.time()

        try:
            import shutil

            # Check database directory
            from models import get_database_url
            db_url = get_database_url()
            db_file = db_url.replace('sqlite:///', '')
            db_dir = os.path.dirname(os.path.abspath(db_file))

            # Check disk space
            disk_usage = shutil.disk_usage(db_dir)
            free_space_gb = disk_usage.free / (1024**3)
            total_space_gb = disk_usage.total / (1024**3)
            used_percent = (disk_usage.used / disk_usage.total) * 100

            # Check GPG home directory
            gpg_home_exists = os.path.exists(self.config.gpg.home)
            gpg_home_writable = os.access(self.config.gpg.home, os.W_OK) if gpg_home_exists else False

            response_time = (time.time() - start_time) * 1000

            status = "healthy"
            if used_percent > 90:
                status = "degraded"
            if used_percent > 95 or free_space_gb < 1:
                status = "unhealthy"

            return HealthStatus(
                service="filesystem",
                status=status,
                timestamp=datetime.utcnow(),
                response_time_ms=response_time,
                details={
                    "database_directory": db_dir,
                    "gpg_home": self.config.gpg.home,
                    "gpg_home_exists": gpg_home_exists,
                    "gpg_home_writable": gpg_home_writable,
                    "disk_free_gb": round(free_space_gb, 2),
                    "disk_total_gb": round(total_space_gb, 2),
                    "disk_used_percent": round(used_percent, 2)
                }
            )

        except Exception as e:
            return HealthStatus(
                service="filesystem",
                status="unhealthy",
                timestamp=datetime.utcnow(),
                response_time_ms=(time.time() - start_time) * 1000,
                details={"error": str(e)}
            )

    def get_overall_health(self) -> Dict[str, Any]:
        """Get overall system health"""
        checks = [
            self.check_database_health(),
            self.check_gpg_health(),
            self.check_filesystem_health()
        ]

        # Determine overall status
        statuses = [check.status for check in checks]
        if any(status == "unhealthy" for status in statuses):
            overall_status = "unhealthy"
        elif any(status == "degraded" for status in statuses):
            overall_status = "degraded"
        else:
            overall_status = "healthy"

        return {
            "status": overall_status,
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {check.service: asdict(check) for check in checks},
            "summary": {
                "total_checks": len(checks),
                "healthy": sum(1 for s in statuses if s == "healthy"),
                "degraded": sum(1 for s in statuses if s == "degraded"),
                "unhealthy": sum(1 for s in statuses if s == "unhealthy")
            }
        }


class MonitoringServer:
    """HTTP server for metrics and health endpoints"""

    def __init__(self, config=None):
        """Initialize monitoring server"""
        self.config = config or get_config()
        self.metrics_collector = MetricsCollector(config)
        self.health_checker = HealthChecker(config)
        self._server_thread = None

    def start_prometheus_server(self):
        """Start Prometheus metrics server"""
        if not PROMETHEUS_AVAILABLE:
            logger.warning("Prometheus client not available, skipping metrics server")
            return

        if not self.config.monitoring.enabled:
            logger.info("Monitoring disabled in configuration")
            return

        try:
            port = self.config.monitoring.prometheus_port
            start_http_server(port, registry=self.metrics_collector.registry)
            logger.info(f"Prometheus metrics server started on port {port}")
        except Exception as e:
            logger.error(f"Failed to start Prometheus server: {e}")

    def start_health_server(self):
        """Start health check HTTP server"""
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
            import json

            health_checker = self.health_checker
            metrics_collector = self.metrics_collector

            class HealthHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path == '/health':
                        health = health_checker.get_overall_health()
                        status_code = 200 if health['status'] == 'healthy' else 503

                        self.send_response(status_code)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps(health, default=str).encode())

                    elif self.path == '/metrics/json':
                        metrics_json = metrics_collector.export_metrics_json()

                        self.send_response(200)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(metrics_json.encode())

                    else:
                        self.send_response(404)
                        self.end_headers()

                def log_message(self, format, *args):
                    # Suppress default logging
                    pass

            port = self.config.monitoring.health_check_port
            server = HTTPServer(('', port), HealthHandler)

            def run_server():
                logger.info(f"Health check server started on port {port}")
                server.serve_forever()

            self._server_thread = threading.Thread(target=run_server, daemon=True)
            self._server_thread.start()

        except Exception as e:
            logger.error(f"Failed to start health check server: {e}")

    def stop(self):
        """Stop monitoring servers"""
        if self._server_thread and self._server_thread.is_alive():
            logger.info("Stopping monitoring servers")


# Global instances
_metrics_collector = None
_health_checker = None
_monitoring_server = None


def get_metrics_collector() -> MetricsCollector:
    """Get global metrics collector instance"""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


def get_health_checker() -> HealthChecker:
    """Get global health checker instance"""
    global _health_checker
    if _health_checker is None:
        _health_checker = HealthChecker()
    return _health_checker


def start_monitoring():
    """Start monitoring services"""
    global _monitoring_server

    config = get_config()
    if not config.monitoring.enabled:
        logger.info("Monitoring is disabled")
        return

    _monitoring_server = MonitoringServer()
    _monitoring_server.start_prometheus_server()
    _monitoring_server.start_health_server()


def stop_monitoring():
    """Stop monitoring services"""
    global _monitoring_server
    if _monitoring_server:
        _monitoring_server.stop()


if __name__ == '__main__':
    # Test monitoring functionality
    print("Testing monitoring functionality...")

    collector = MetricsCollector()
    health = HealthChecker()

    # Test metrics collection
    with collector.operation_timer('test_operation'):
        time.sleep(0.1)

    metrics = collector.get_current_metrics()
    print(f"Current metrics: {asdict(metrics)}")

    # Test health checks
    health_status = health.get_overall_health()
    print(f"Health status: {health_status}")

    # Test JSON export
    metrics_json = collector.export_metrics_json()
    print(f"Metrics JSON: {metrics_json[:200]}...")

    print("Monitoring test completed")