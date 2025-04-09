from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import boto3
import json
import os
from ..base_agent import BaseLogAgent

class AWSAgent(BaseLogAgent):
    def __init__(self, config_path: str):
        super().__init__(config_path)
        self.regions = self.config.get('regions', ['us-east-1'])
        self.services = self.config.get('services', ['CloudTrail', 'GuardDuty', 'SecurityHub'])
        self.credentials = {
            'aws_access_key_id': os.getenv('AWS_ACCESS_KEY', self.config.get('credentials', {}).get('access_key', '')),
            'aws_secret_access_key': os.getenv('AWS_SECRET_KEY', self.config.get('credentials', {}).get('secret_key', ''))
        }
        self.clients = {}

    def connect(self) -> bool:
        """Establish connections to AWS services"""
        try:
            for region in self.regions:
                self.clients[region] = {}
                for service in self.services:
                    service_name = service.lower()
                    if service == 'CloudTrail':
                        self.clients[region][service_name] = boto3.client(
                            'cloudtrail',
                            region_name=region,
                            **self.credentials
                        )
                    elif service == 'GuardDuty':
                        self.clients[region][service_name] = boto3.client(
                            'guardduty',
                            region_name=region,
                            **self.credentials
                        )
                    elif service == 'SecurityHub':
                        self.clients[region][service_name] = boto3.client(
                            'securityhub',
                            region_name=region,
                            **self.credentials
                        )
            return True
        except Exception as e:
            print(f"Failed to connect to AWS services: {e}")
            return False

    def disconnect(self) -> None:
        """Close AWS service connections"""
        self.clients.clear()

    def fetch_logs(self, start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch logs from AWS services"""
        if not start_time:
            start_time = datetime.now() - timedelta(hours=1)
        if not end_time:
            end_time = datetime.now()

        all_logs = []
        for region, services in self.clients.items():
            for service_name, client in services.items():
                try:
                    if service_name == 'cloudtrail':
                        logs = self._fetch_cloudtrail_logs(client, start_time, end_time)
                    elif service_name == 'guardduty':
                        logs = self._fetch_guardduty_findings(client, start_time, end_time)
                    elif service_name == 'securityhub':
                        logs = self._fetch_securityhub_findings(client, start_time, end_time)
                    all_logs.extend(logs)
                except Exception as e:
                    print(f"Error fetching {service_name} logs from {region}: {e}")

        return all_logs

    def _fetch_cloudtrail_logs(self, client, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Fetch CloudTrail logs"""
        logs = []
        try:
            response = client.lookup_events(
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=self.batch_size
            )
            for event in response.get('Events', []):
                logs.append({
                    'service': 'cloudtrail',
                    'raw': json.dumps(event),
                    'timestamp': event.get('EventTime', '').isoformat(),
                    'source': 'aws',
                    'event_type': event.get('EventName', 'unknown'),
                    'user': event.get('Username', 'unknown'),
                    'source_ip': event.get('SourceIPAddress', ''),
                    'action': event.get('EventName', ''),
                    'status': event.get('ResponseElements', {}).get('status', ''),
                    'message': event.get('CloudTrailEvent', '')
                })
        except Exception as e:
            print(f"Error fetching CloudTrail logs: {e}")
        return logs

    def _fetch_guardduty_findings(self, client, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Fetch GuardDuty findings"""
        logs = []
        try:
            response = client.list_findings(
                DetectorId=self._get_detector_id(client),
                FindingCriteria={
                    'Criterion': {
                        'updatedAt': {
                            'Gte': int(start_time.timestamp() * 1000),
                            'Lte': int(end_time.timestamp() * 1000)
                        }
                    }
                },
                MaxResults=self.batch_size
            )
            findings = client.get_findings(
                DetectorId=self._get_detector_id(client),
                FindingIds=response.get('FindingIds', [])
            )
            for finding in findings.get('Findings', []):
                logs.append({
                    'service': 'guardduty',
                    'raw': json.dumps(finding),
                    'timestamp': finding.get('UpdatedAt', '').isoformat(),
                    'source': 'aws',
                    'event_type': finding.get('Type', 'unknown'),
                    'severity': self._map_guardduty_severity(finding.get('Severity', 0)),
                    'source_ip': finding.get('Service', {}).get('Action', {}).get('NetworkConnectionAction', {}).get('RemoteIpDetails', {}).get('IpAddressV4', ''),
                    'action': finding.get('Service', {}).get('Action', {}).get('ActionType', ''),
                    'status': finding.get('Service', {}).get('Action', {}).get('NetworkConnectionAction', {}).get('ConnectionDirection', ''),
                    'message': finding.get('Description', '')
                })
        except Exception as e:
            print(f"Error fetching GuardDuty findings: {e}")
        return logs

    def _fetch_securityhub_findings(self, client, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Fetch SecurityHub findings"""
        logs = []
        try:
            response = client.get_findings(
                Filters={
                    'UpdatedAt': [{
                        'Gte': start_time.isoformat(),
                        'Lte': end_time.isoformat()
                    }]
                },
                MaxResults=self.batch_size
            )
            for finding in response.get('Findings', []):
                logs.append({
                    'service': 'securityhub',
                    'raw': json.dumps(finding),
                    'timestamp': finding.get('UpdatedAt', '').isoformat(),
                    'source': 'aws',
                    'event_type': finding.get('Type', 'unknown'),
                    'severity': self._map_securityhub_severity(finding.get('Severity', {}).get('Normalized', 0)),
                    'source_ip': finding.get('Resources', [{}])[0].get('Details', {}).get('AwsEc2Instance', {}).get('PublicIpAddress', ''),
                    'action': finding.get('Remediation', {}).get('Recommendation', {}).get('Text', ''),
                    'status': finding.get('RecordState', ''),
                    'message': finding.get('Description', '')
                })
        except Exception as e:
            print(f"Error fetching SecurityHub findings: {e}")
        return logs

    def _get_detector_id(self, client) -> str:
        """Get the GuardDuty detector ID"""
        response = client.list_detectors()
        return response.get('DetectorIds', [''])[0]

    def _map_guardduty_severity(self, severity: float) -> str:
        """Map GuardDuty severity to standard severity levels"""
        if severity >= 7:
            return 'critical'
        elif severity >= 4:
            return 'high'
        elif severity >= 2:
            return 'medium'
        else:
            return 'low'

    def _map_securityhub_severity(self, severity: int) -> str:
        """Map SecurityHub severity to standard severity levels"""
        if severity >= 70:
            return 'critical'
        elif severity >= 40:
            return 'high'
        elif severity >= 20:
            return 'medium'
        else:
            return 'low'

    def parse_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and normalize an AWS log entry"""
        return log  # Already normalized in fetch methods 