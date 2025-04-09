import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, List
import uvicorn
from dotenv import load_dotenv

from agents.splunk.splunk_agent import SplunkAgent
from agents.gcp.gcp_agent import GCPAgent
from agents.azure.azure_agent import AzureAgent
from analysis.llm.engine import LLMAnalysisEngine
from analysis.message_bus import MessageBus
from notifications.notifier import Notifier

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(
    title="AluhaSOC",
    description="AI-powered Security Operations Center",
    version="1.0.0"
)

# Initialize components
message_bus = MessageBus(
    host=os.getenv('RABBITMQ_HOST', 'localhost'),
    port=int(os.getenv('RABBITMQ_PORT', 5672))
)

llm_engine = LLMAnalysisEngine('config/llm.yaml')
notifier = Notifier('config/notifications.yaml')

# Initialize log agents
log_agents = {
    'splunk': SplunkAgent('config/log_sources.yaml'),
    'gcp': GCPAgent('config/log_sources.yaml'),
    'azure': AzureAgent('config/log_sources.yaml')
    # Add other agents here
}

class SecurityEvent(BaseModel):
    source: str
    event_type: str
    severity: str
    description: str
    raw_data: Dict[str, Any]

class AnalysisRequest(BaseModel):
    event_id: str
    event_type: str
    raw_data: Dict[str, Any]

@app.get("/")
async def root():
    return {"message": "Welcome to AluhaSOC API"}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "components": {
            "message_bus": message_bus.connection is not None,
            "llm_engine": llm_engine.model is not None,
            "log_agents": {name: agent.get_status() for name, agent in log_agents.items()}
        }
    }

@app.post("/events")
async def process_event(event: SecurityEvent):
    try:
        # Analyze event using LLM
        analysis = llm_engine.analyze_security_event(event.dict())
        
        # Send alert if severity is high enough
        if analysis['severity'] in ['critical', 'high']:
            alert = {
                'title': f"Security Event: {event.event_type}",
                'severity': analysis['severity'],
                'source': event.source,
                'description': event.description,
                'impact': analysis['impact'],
                'recommendations': analysis['recommendations'],
                'additional_info': {
                    'raw_data': event.raw_data,
                    'iocs': analysis['iocs']
                }
            }
            notifier.send_alert(alert)
        
        return {
            "status": "success",
            "event_id": event.raw_data.get('id'),
            "analysis": analysis
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze")
async def analyze_event(request: AnalysisRequest):
    try:
        analysis = llm_engine.analyze_security_event(request.raw_data)
        return {
            "status": "success",
            "event_id": request.event_id,
            "analysis": analysis
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/agents/{agent_name}/status")
async def get_agent_status(agent_name: str):
    if agent_name not in log_agents:
        raise HTTPException(status_code=404, detail="Agent not found")
    return log_agents[agent_name].get_status()

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        reload=True
    ) 