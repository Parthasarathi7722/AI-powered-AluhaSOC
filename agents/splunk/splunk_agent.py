from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import splunklib.client as splunk
from splunklib.client import Service
import os
from ..base_agent import BaseLogAgent

class SplunkAgent(BaseLogAgent):
    def __init__(self, config_path: str):
        super().__init__(config_path)
        self.service = None
        self.index = self.config.get('index', 'main')
        self.search_interval = self.config.get('search_interval', 300)

    def connect(self) -> bool:
        try:
            self.service = Service(
                host=self.config['host'],
                port=self.config['port'],
                username=self.config['username'],
                password=os.getenv('SPLUNK_PASSWORD', self.config['password'])
            )
            return True
        except Exception as e:
            print(f"Failed to connect to Splunk: {e}")
            return False

    def disconnect(self) -> None:
        if self.service:
            self.service.logout()

    def fetch_logs(self, start_time: Optional[datetime] = None,
                  end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        if not start_time:
            start_time = datetime.now() - timedelta(seconds=self.search_interval)
        if not end_time:
            end_time = datetime.now()

        search_query = f'search index={self.index} earliest={start_time.strftime("%Y-%m-%d %H:%M:%S")} latest={end_time.strftime("%Y-%m-%d %H:%M:%S")}'
        
        try:
            job = self.service.jobs.create(search_query)
            while not job.is_done():
                time.sleep(1)
            
            result_count = int(job["resultCount"])
            if result_count == 0:
                return []

            result_stream = job.results(count=0)
            logs = []
            for result in result_stream:
                logs.append(dict(result))
            
            return logs

        except Exception as e:
            print(f"Error fetching logs from Splunk: {e}")
            return []

    def parse_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and normalize a Splunk log entry"""
        try:
            return {
                'timestamp': log.get('_time', datetime.now().isoformat()),
                'source': log.get('source', 'unknown'),
                'sourcetype': log.get('sourcetype', 'unknown'),
                'host': log.get('host', 'unknown'),
                'raw': log.get('_raw', ''),
                'severity': log.get('severity', 'info'),
                'event_type': log.get('eventtype', 'unknown'),
                'source_ip': log.get('src_ip', ''),
                'destination_ip': log.get('dest_ip', ''),
                'user': log.get('user', ''),
                'action': log.get('action', ''),
                'status': log.get('status', ''),
                'message': log.get('message', '')
            }
        except Exception as e:
            print(f"Error parsing log: {e}")
            return {} 