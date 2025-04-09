from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from google.cloud import securitycenter_v1
from google.cloud import monitoring_v3
from google.cloud import logging_v2
import json
import os
from ..base_agent import BaseLogAgent

class GCPAgent(BaseLogAgent):
    def __init__(self, config_path: str):
        super().__init__(config_path)
        self.project_id = os.getenv('GCP_PROJECT_ID', 
                                   self.config.get('project_id', ''))
        self.services = self.config.get('services', ['SecurityCommandCenter', 'CloudMonitoring', 'CloudLogging'])
        self.clients = {}

    def connect(self) -> bool:
        """Establish connections to GCP services"""
        try:
            if 'SecurityCommandCenter' in self.services:
                self.clients['security_center'] = securitycenter_v1.SecurityCenterClient()
            
            if 'CloudMonitoring' in self.services:
                self.clients['monitoring'] = monitoring_v3.MetricServiceClient()
            
            if 'CloudLogging' in self.services:
                self.clients['logging'] = logging_v2.LoggingServiceV2Client()
            
            return True
        except Exception as e:
            print(f"Failed to connect to GCP services: {e}")
            return False

    def disconnect(self) -> None:
        """Close GCP service connections"""
        self.clients.clear()

    def fetch_logs(self, start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch logs from GCP services"""
        if not start_time:
            start_time = datetime.now() - timedelta(hours=1)
        if not end_time:
            end_time = datetime.now()

        all_logs = []
        
        if 'security_center' in self.clients:
            try:
                security_logs = self._fetch_security_center_logs(start_time, end_time)
                all_logs.extend(security_logs)
            except Exception as e:
                print(f"Error fetching Security Command Center logs: {e}")

        if 'monitoring' in self.clients:
            try:
                monitoring_logs = self._fetch_monitoring_logs(start_time, end_time)
                all_logs.extend(monitoring_logs)
            except Exception as e:
                print(f"Error fetching Cloud Monitoring logs: {e}")

        if 'logging' in self.clients:
            try:
                cloud_logs = self._fetch_cloud_logging_logs(start_time, end_time)
                all_logs.extend(cloud_logs)
            except Exception as e:
                print(f"Error fetching Cloud Logging logs: {e}")

        return all_logs

    def _fetch_security_center_logs(self, start_time: datetime, 
                                  end_time: datetime) -> List[Dict[str, Any]]:
        """Fetch logs from Security Command Center"""
        logs = []
        try:
            # Get findings
            request = securitycenter_v1.ListFindingsRequest(
                parent=f"organizations/{self.config.get('organization_id')}/sources/-",
                filter=f"state = \"ACTIVE\" AND eventTime >= \"{start_time.isoformat()}\" AND eventTime <= \"{end_time.isoformat()}\""
            )
            
            for finding in self.clients['security_center'].list_findings(request=request):
                logs.append({
                    'service': 'security_command_center',
                    'raw': json.dumps(finding.to_dict()),
                    'timestamp': finding.event_time.isoformat(),
                    'source': 'gcp',
                    'event_type': finding.category,
                    'severity': self._map_security_center_severity(finding.severity),
                    'source_ip': finding.source_properties.get('source_ip', ''),
                    'action': finding.state,
                    'status': finding.state,
                    'message': finding.description
                })
        except Exception as e:
            print(f"Error processing Security Command Center logs: {e}")
        return logs

    def _fetch_monitoring_logs(self, start_time: datetime, 
                             end_time: datetime) -> List[Dict[str, Any]]:
        """Fetch logs from Cloud Monitoring"""
        logs = []
        try:
            project_name = self.clients['monitoring'].project_path(self.project_id)
            
            # Get alerting policy violations
            interval = monitoring_v3.TimeInterval({
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat()
            })
            
            request = monitoring_v3.ListTimeSeriesRequest(
                name=project_name,
                filter='metric.type = "monitoring.googleapis.com/alerting/violations"',
                interval=interval
            )
            
            for time_series in self.clients['monitoring'].list_time_series(request=request):
                for point in time_series.points:
                    logs.append({
                        'service': 'cloud_monitoring',
                        'raw': json.dumps(time_series.to_dict()),
                        'timestamp': point.interval.start_time.isoformat(),
                        'source': 'gcp',
                        'event_type': time_series.metric.type,
                        'severity': self._map_monitoring_severity(point.value.double_value),
                        'source_ip': '',
                        'action': 'alert',
                        'status': 'active',
                        'message': f"Alert: {time_series.metric.type} - {point.value.double_value}"
                    })
        except Exception as e:
            print(f"Error processing Cloud Monitoring logs: {e}")
        return logs

    def _fetch_cloud_logging_logs(self, start_time: datetime, 
                                end_time: datetime) -> List[Dict[str, Any]]:
        """Fetch logs from Cloud Logging"""
        logs = []
        try:
            resource_names = [f"projects/{self.project_id}"]
            
            filter_query = (
                f"timestamp >= \"{start_time.isoformat()}\" AND "
                f"timestamp <= \"{end_time.isoformat()}\" AND "
                "severity >= WARNING"
            )
            
            request = logging_v2.ListLogEntriesRequest(
                resource_names=resource_names,
                filter=filter_query,
                order_by="timestamp desc"
            )
            
            for entry in self.clients['logging'].list_log_entries(request=request):
                logs.append({
                    'service': 'cloud_logging',
                    'raw': json.dumps(entry.to_dict()),
                    'timestamp': entry.timestamp.isoformat(),
                    'source': 'gcp',
                    'event_type': entry.severity.name,
                    'severity': self._map_logging_severity(entry.severity),
                    'source_ip': entry.resource.labels.get('source_ip', ''),
                    'action': entry.resource.type,
                    'status': entry.severity.name,
                    'message': entry.text_payload or entry.json_payload
                })
        except Exception as e:
            print(f"Error processing Cloud Logging logs: {e}")
        return logs

    def _map_security_center_severity(self, severity: str) -> str:
        """Map Security Command Center severity to standard severity levels"""
        severity_map = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
        return severity_map.get(severity, 'low')

    def _map_monitoring_severity(self, value: float) -> str:
        """Map Monitoring metric value to standard severity levels"""
        if value >= 0.8:
            return 'critical'
        elif value >= 0.6:
            return 'high'
        elif value >= 0.4:
            return 'medium'
        return 'low'

    def _map_logging_severity(self, severity: str) -> str:
        """Map Cloud Logging severity to standard severity levels"""
        severity_map = {
            'CRITICAL': 'critical',
            'ERROR': 'high',
            'WARNING': 'medium',
            'INFO': 'low'
        }
        return severity_map.get(severity, 'low')

    def parse_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and normalize a GCP log entry"""
        return log  # Already normalized in fetch methods 