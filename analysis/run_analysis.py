import os
import logging
from typing import Dict, Any
from dotenv import load_dotenv

from .llm.engine import LLMAnalysisEngine
from .message_bus import MessageBus
from notifications.notifier import Notifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

class AnalysisRunner:
    def __init__(self):
        self.message_bus = MessageBus(
            host=os.getenv('RABBITMQ_HOST', 'localhost'),
            port=int(os.getenv('RABBITMQ_PORT', 5672))
        )
        self.llm_engine = LLMAnalysisEngine('config/llm.yaml')
        self.notifier = Notifier('config/notifications.yaml')

    def process_event(self, event: Dict[str, Any]):
        """Process a security event"""
        try:
            # Analyze event using LLM
            analysis = self.llm_engine.analyze_security_event(event)
            logger.info(f"Analyzed event {event.get('id', 'unknown')}")

            # Send alert if severity is high enough
            if analysis['severity'] in ['critical', 'high']:
                alert = {
                    'title': f"Security Event: {event.get('event_type', 'Unknown')}",
                    'severity': analysis['severity'],
                    'source': event.get('source', 'Unknown'),
                    'description': event.get('description', 'No description'),
                    'impact': analysis['impact'],
                    'recommendations': analysis['recommendations'],
                    'additional_info': {
                        'raw_data': event,
                        'iocs': analysis['iocs']
                    }
                }
                self.notifier.send_alert(alert)
                logger.info(f"Sent alert for event {event.get('id', 'unknown')}")

            # Publish analysis results
            self.message_bus.publish(
                'security_analysis',
                {
                    'event_id': event.get('id'),
                    'analysis': analysis
                }
            )
            logger.info(f"Published analysis for event {event.get('id', 'unknown')}")

        except Exception as e:
            logger.error(f"Error processing event: {e}")

    def run(self):
        """Run the analysis engine"""
        try:
            logger.info("Starting analysis engine")
            
            def process_message(message: Dict[str, Any]):
                self.process_event(message)

            # Consume messages from the security_logs queue
            self.message_bus.consume('security_logs', process_message)

        except Exception as e:
            logger.error(f"Error in analysis engine: {e}")
        finally:
            self.message_bus.close()

def main():
    runner = AnalysisRunner()
    try:
        runner.run()
    except KeyboardInterrupt:
        logger.info("Stopping analysis engine")
    except Exception as e:
        logger.error(f"Error in analysis runner: {e}")

if __name__ == "__main__":
    main() 