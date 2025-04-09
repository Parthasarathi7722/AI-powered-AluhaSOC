from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import yaml
import os
from datetime import datetime

class BaseLogAgent(ABC):
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.last_run = None
        self.batch_size = self.config.get('batch_size', 1000)

    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to the log source"""
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """Close connection to the log source"""
        pass

    @abstractmethod
    def fetch_logs(self, start_time: Optional[datetime] = None, 
                  end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Fetch logs from the source"""
        pass

    @abstractmethod
    def parse_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Parse and normalize a single log entry"""
        pass

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)

    def process_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process a batch of logs"""
        processed_logs = []
        for log in logs:
            try:
                processed_log = self.parse_log(log)
                processed_logs.append(processed_log)
            except Exception as e:
                print(f"Error processing log: {e}")
                continue
        return processed_logs

    def run(self) -> List[Dict[str, Any]]:
        """Main execution method"""
        try:
            if not self.connect():
                raise ConnectionError("Failed to connect to log source")

            logs = self.fetch_logs()
            processed_logs = self.process_logs(logs)
            self.last_run = datetime.now()

            return processed_logs

        except Exception as e:
            print(f"Error in agent execution: {e}")
            return []

        finally:
            self.disconnect()

    def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            'last_run': self.last_run,
            'connected': self.connect(),
            'config': self.config
        } 