import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
import yaml
from typing import Dict, Any, List
import os
from pathlib import Path

class LLMAnalysisEngine:
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.device = torch.device(self.config['inference']['device'])
        self.model = None
        self.tokenizer = None
        self._load_model()

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load LLM configuration"""
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)

    def _load_model(self):
        """Load and optimize the LLM"""
        try:
            model_config = self.config['model']
            model_path = os.getenv('MODEL_PATH', f"models/{model_config['name']}")

            # Load tokenizer
            self.tokenizer = AutoTokenizer.from_pretrained(model_path)
            
            # Load model with quantization if specified
            if model_config['quantization'] == 'int8':
                self.model = AutoModelForCausalLM.from_pretrained(
                    model_path,
                    load_in_8bit=True,
                    device_map='auto'
                )
            else:
                self.model = AutoModelForCausalLM.from_pretrained(model_path)
                self.model = self.model.to(self.device)

            # Set model parameters
            self.model.config.temperature = model_config['temperature']
            self.model.config.top_p = model_config['top_p']
            self.model.config.repetition_penalty = model_config['repetition_penalty']

        except Exception as e:
            print(f"Error loading model: {e}")
            raise

    def analyze_security_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a security event using the LLM"""
        try:
            # Prepare the prompt
            prompt = self.config['prompts']['security_analysis'].format(
                event_details=self._format_event_details(event)
            )

            # Generate analysis
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.device)
            outputs = self.model.generate(
                **inputs,
                max_length=self.config['model']['max_length'],
                num_return_sequences=1,
                pad_token_id=self.tokenizer.eos_token_id
            )

            # Parse the response
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            return self._parse_analysis_response(response)

        except Exception as e:
            print(f"Error analyzing security event: {e}")
            return {
                'severity': 'unknown',
                'impact': 'Error during analysis',
                'recommendations': ['Investigate analysis error'],
                'iocs': []
            }

    def summarize_incident(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Generate an incident summary using the LLM"""
        try:
            # Prepare the prompt
            prompt = self.config['prompts']['incident_summary'].format(
                incident_details=self._format_incident_details(incident)
            )

            # Generate summary
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.device)
            outputs = self.model.generate(
                **inputs,
                max_length=self.config['model']['max_length'],
                num_return_sequences=1,
                pad_token_id=self.tokenizer.eos_token_id
            )

            # Parse the response
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            return self._parse_summary_response(response)

        except Exception as e:
            print(f"Error summarizing incident: {e}")
            return {
                'timeline': [],
                'root_cause': 'Error during analysis',
                'impact': 'Error during analysis',
                'remediation': ['Investigate analysis error']
            }

    def _format_event_details(self, event: Dict[str, Any]) -> str:
        """Format event details for the prompt"""
        return f"""
        Timestamp: {event.get('timestamp', 'unknown')}
        Source: {event.get('source', 'unknown')}
        Event Type: {event.get('event_type', 'unknown')}
        Severity: {event.get('severity', 'unknown')}
        Source IP: {event.get('source_ip', 'unknown')}
        Destination IP: {event.get('destination_ip', 'unknown')}
        User: {event.get('user', 'unknown')}
        Action: {event.get('action', 'unknown')}
        Status: {event.get('status', 'unknown')}
        Message: {event.get('message', 'unknown')}
        """

    def _format_incident_details(self, incident: Dict[str, Any]) -> str:
        """Format incident details for the prompt"""
        return f"""
        Incident ID: {incident.get('id', 'unknown')}
        Start Time: {incident.get('start_time', 'unknown')}
        End Time: {incident.get('end_time', 'unknown')}
        Status: {incident.get('status', 'unknown')}
        Events: {len(incident.get('events', []))}
        Affected Systems: {', '.join(incident.get('affected_systems', []))}
        Description: {incident.get('description', 'unknown')}
        """

    def _parse_analysis_response(self, response: str) -> Dict[str, Any]:
        """Parse the LLM's security analysis response"""
        # This is a simple parser - you might want to make it more robust
        lines = response.split('\n')
        result = {
            'severity': 'unknown',
            'impact': '',
            'recommendations': [],
            'iocs': []
        }

        current_section = None
        for line in lines:
            line = line.strip()
            if not line:
                continue

            if 'severity' in line.lower():
                result['severity'] = line.split(':')[-1].strip()
            elif 'impact' in line.lower():
                current_section = 'impact'
            elif 'recommend' in line.lower():
                current_section = 'recommendations'
            elif 'indicator' in line.lower():
                current_section = 'iocs'
            elif current_section == 'impact':
                result['impact'] += line + ' '
            elif current_section == 'recommendations':
                result['recommendations'].append(line)
            elif current_section == 'iocs':
                result['iocs'].append(line)

        return result

    def _parse_summary_response(self, response: str) -> Dict[str, Any]:
        """Parse the LLM's incident summary response"""
        # This is a simple parser - you might want to make it more robust
        lines = response.split('\n')
        result = {
            'timeline': [],
            'root_cause': '',
            'impact': '',
            'remediation': []
        }

        current_section = None
        for line in lines:
            line = line.strip()
            if not line:
                continue

            if 'timeline' in line.lower():
                current_section = 'timeline'
            elif 'root cause' in line.lower():
                current_section = 'root_cause'
            elif 'impact' in line.lower():
                current_section = 'impact'
            elif 'remediation' in line.lower():
                current_section = 'remediation'
            elif current_section == 'timeline':
                result['timeline'].append(line)
            elif current_section == 'root_cause':
                result['root_cause'] += line + ' '
            elif current_section == 'impact':
                result['impact'] += line + ' '
            elif current_section == 'remediation':
                result['remediation'].append(line)

        return result 