import os
import time
import logging
from typing import Dict, Type
from dotenv import load_dotenv

from .base_agent import BaseLogAgent
from .splunk.splunk_agent import SplunkAgent
# Import other agents here

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Define available agents
AGENTS: Dict[str, Type[BaseLogAgent]] = {
    'splunk': SplunkAgent,
    # Add other agents here
}

class AgentRunner:
    def __init__(self):
        self.agents = {}
        self.running = True
        self._initialize_agents()

    def _initialize_agents(self):
        """Initialize all configured agents"""
        for name, agent_class in AGENTS.items():
            try:
                self.agents[name] = agent_class('config/log_sources.yaml')
                logger.info(f"Initialized {name} agent")
            except Exception as e:
                logger.error(f"Failed to initialize {name} agent: {e}")

    def run_agent(self, agent_name: str):
        """Run a single agent"""
        if agent_name not in self.agents:
            logger.error(f"Agent {agent_name} not found")
            return

        agent = self.agents[agent_name]
        try:
            logger.info(f"Running {agent_name} agent")
            logs = agent.run()
            if logs:
                logger.info(f"Collected {len(logs)} logs from {agent_name}")
                # Process logs here (e.g., send to message bus)
            else:
                logger.info(f"No new logs from {agent_name}")
        except Exception as e:
            logger.error(f"Error running {agent_name} agent: {e}")

    def run_all(self):
        """Run all agents"""
        while self.running:
            for agent_name in self.agents:
                self.run_agent(agent_name)
            time.sleep(60)  # Wait before next iteration

    def stop(self):
        """Stop all agents"""
        self.running = False
        for agent in self.agents.values():
            try:
                agent.disconnect()
            except Exception as e:
                logger.error(f"Error disconnecting agent: {e}")

def main():
    runner = AgentRunner()
    try:
        logger.info("Starting log collection agents")
        runner.run_all()
    except KeyboardInterrupt:
        logger.info("Stopping log collection agents")
        runner.stop()
    except Exception as e:
        logger.error(f"Error in agent runner: {e}")
        runner.stop()

if __name__ == "__main__":
    main() 