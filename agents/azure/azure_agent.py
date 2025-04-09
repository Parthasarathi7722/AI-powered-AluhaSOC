from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from azure.identity import DefaultAzureCredential
from azure.mgmt.security import SecurityCenter
from azure.monitor import MonitorClient
import json
import os
from ..base_agent import BaseLogAgent

class AzureAgent(BaseLogAgent):
    def __init__(self, config_path: str):
        super().__init__(config_path)
        self.subscription_id = os.getenv('AZURE_SUBSCRIPTION_ID', 
                                       self.config.get('subscription_id', ''))
        self.tenant_id = os.getenv('AZURE_TENANT_ID',
                                  self.config.get('tenant_id', ''))
        self.services = self.config.get('services', ['SecurityCenter', 'Monitor'])
        self.clients = {}

    def connect(self) -> bool:
        """Establish connections to Azure services"""
        try:
            credential = DefaultAzureCredential()
            
            if 'SecurityCenter' in self.services:
                self.clients['security_center'] = SecurityCenter(
                    credential=credential,
                    subscription_id=self.subscription_id
                )
            
            if 'Monitor' in self.services:
                self.clients['monitor'] = MonitorClient(
                    credential=credential,
                    subscription_id=self.subscription_id
                )
            
            return True
        except Exception as e:
            print(f"Failed to connect to Azure services: {e}")
            return False

    def disconnect(self) -> None:
        """Close Azure service connections"""
        self.clients.clear()

    def fetch_logs(self, start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch logs from Azure services"""
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
                print(f"Error fetching Security Center logs: {e}")

        if 'monitor' in self.clients:
            try:
                monitor_logs = self._fetch_monitor_logs(start_time, end_time)
                all_logs.extend(monitor_logs)
            except Exception as e:
                print(f"Error fetching Monitor logs: {e}")

        return all_logs

    def _fetch_security_center_logs(self, start_time: datetime, 
                                  end_time: datetime) -> List[Dict[str, Any]]:
        """Fetch logs from Azure Security Center"""
        logs = []
        try:
            # Get security alerts
            alerts = self.clients['security_center'].alerts.list()
            for alert in alerts:
                if start_time <= alert.reported_time <= end_time:
                    logs.append({
                        'service': 'security_center',
                        'raw': json.dumps(alert.as_dict()),
                        'timestamp': alert.reported_time.isoformat(),
                        'source': 'azure',
                        'event_type': alert.alert_type,
                        'severity': self._map_security_center_severity(alert.severity),
                        'source_ip': alert.extended_properties.get('source_ip', ''),
                        'action': alert.recommended_action,
                        'status': alert.state,
                        'message': alert.description
                    })

            # Get security recommendations
            recommendations = self.clients['security_center'].assessments.list()
            for rec in recommendations:
                if start_time <= rec.assessment_date <= end_time:
                    logs.append({
                        'service': 'security_center',
                        'raw': json.dumps(rec.as_dict()),
                        'timestamp': rec.assessment_date.isoformat(),
                        'source': 'azure',
                        'event_type': 'recommendation',
                        'severity': self._map_security_center_severity(rec.severity),
                        'source_ip': '',
                        'action': rec.remediation,
                        'status': rec.status.code,
                        'message': rec.display_name
                    })
        except Exception as e:
            print(f"Error processing Security Center logs: {e}")
        return logs

    def _fetch_monitor_logs(self, start_time: datetime, 
                          end_time: datetime) -> List[Dict[str, Any]]:
        """Fetch logs from Azure Monitor"""
        logs = []
        try:
            # Get activity logs
            filter_query = (
                f"eventTimestamp ge '{start_time.isoformat()}' and "
                f"eventTimestamp le '{end_time.isoformat()}'"
            )
            activity_logs = self.clients['monitor'].activity_logs.list(
                filter=filter_query
            )
            
            for log in activity_logs:
                logs.append({
                    'service': 'monitor',
                    'raw': json.dumps(log.as_dict()),
                    'timestamp': log.event_timestamp.isoformat(),
                    'source': 'azure',
                    'event_type': log.operation_name.value,
                    'severity': self._map_monitor_severity(log.level),
                    'source_ip': log.caller,
                    'action': log.operation_name.value,
                    'status': log.status.value,
                    'message': log.description
                })
        except Exception as e:
            print(f"Error processing Monitor logs: {e}")
        return logs

    def _map_security_center_severity(self, severity: str) -> str:
        """Map Security Center severity to standard severity levels"""
        severity_map = {
            'Critical': 'critical',
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low'
        }
        return severity_map.get(severity, 'low')

    def _map_monitor_severity(self, level: str) -> str:
        """Map Monitor log level to standard severity levels"""
        level_map = {
            'Critical': 'critical',
            'Error': 'high',
            'Warning': 'medium',
            'Informational': 'low'
        }
        return level_map.get(level, 'low')

    def parse_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and normalize an Azure log entry"""
        return log  # Already normalized in fetch methods 