from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import requests
import json
import os
from ..base_agent import BaseLogAgent

class WazuhAgent(BaseLogAgent):
    def __init__(self, config_path: str):
        super().__init__(config_path)
        self.api_key = os.getenv('WAZUH_API_KEY', self.config.get('api_key', ''))
        self.api_port = self.config.get('api_port', 55000)
        self.cluster_name = self.config.get('cluster_name', 'wazuh-cluster')
        self.base_url = f"https://{self.config['host']}:{self.api_port}"
        self.session = None

    def connect(self) -> bool:
        """Establish connection to Wazuh API"""
        try:
            self.session = requests.Session()
            self.session.verify = False  # For self-signed certificates
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            })
            
            # Test connection
            response = self.session.get(f"{self.base_url}/security/user/authenticate")
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Failed to connect to Wazuh: {e}")
            return False

    def disconnect(self) -> None:
        """Close connection to Wazuh API"""
        if self.session:
            self.session.close()

    def fetch_logs(self, start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch logs from Wazuh API"""
        if not start_time:
            start_time = datetime.now() - timedelta(hours=1)
        if not end_time:
            end_time = datetime.now()

        try:
            # Query Wazuh API for alerts
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"timestamp": {
                                "gte": start_time.isoformat(),
                                "lte": end_time.isoformat()
                            }}}
                        ]
                    }
                },
                "sort": [{"timestamp": "asc"}],
                "size": self.batch_size
            }

            response = self.session.post(
                f"{self.base_url}/alerts",
                json=query
            )
            response.raise_for_status()
            
            data = response.json()
            return data.get('hits', {}).get('hits', [])

        except Exception as e:
            print(f"Error fetching logs from Wazuh: {e}")
            return []

    def parse_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and normalize a Wazuh log entry"""
        try:
            source = log.get('_source', {})
            return {
                'timestamp': source.get('timestamp', datetime.now().isoformat()),
                'source': 'wazuh',
                'agent': source.get('agent', {}).get('name', 'unknown'),
                'rule': source.get('rule', {}).get('level', 'unknown'),
                'severity': self._map_severity(source.get('rule', {}).get('level', 0)),
                'event_type': source.get('rule', {}).get('description', 'unknown'),
                'source_ip': source.get('sourceip', ''),
                'destination_ip': source.get('destinationip', ''),
                'user': source.get('data', {}).get('win', {}).get('eventdata', {}).get('user', ''),
                'action': source.get('rule', {}).get('action', ''),
                'status': source.get('rule', {}).get('status', ''),
                'message': source.get('rule', {}).get('description', ''),
                'raw': json.dumps(source)
            }
        except Exception as e:
            print(f"Error parsing Wazuh log: {e}")
            return {}

    def _map_severity(self, level: int) -> str:
        """Map Wazuh rule level to severity"""
        if level >= 15:
            return 'critical'
        elif level >= 10:
            return 'high'
        elif level >= 5:
            return 'medium'
        else:
            return 'low' 