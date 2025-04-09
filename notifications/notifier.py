import os
from typing import Dict, Any, List
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import json
from datetime import datetime

class Notifier:
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.slack_webhook_url = os.getenv('SLACK_WEBHOOK_URL')
        self.smtp_config = {
            'server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
            'port': int(os.getenv('SMTP_PORT', '587')),
            'username': os.getenv('SMTP_USERNAME'),
            'password': os.getenv('SMTP_PASSWORD'),
            'from_email': os.getenv('FROM_EMAIL')
        }

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load notification configuration"""
        with open(config_path, 'r') as f:
            return json.load(f)

    def send_alert(self, alert: Dict[str, Any], channels: List[str] = None):
        """Send alert through specified channels"""
        if not channels:
            channels = ['slack', 'email']

        for channel in channels:
            try:
                if channel == 'slack':
                    self._send_slack_alert(alert)
                elif channel == 'email':
                    self._send_email_alert(alert)
            except Exception as e:
                print(f"Error sending alert via {channel}: {e}")

    def _send_slack_alert(self, alert: Dict[str, Any]):
        """Send alert to Slack"""
        if not self.slack_webhook_url:
            raise ValueError("Slack webhook URL not configured")

        severity_colors = {
            'critical': '#FF0000',
            'high': '#FFA500',
            'medium': '#FFFF00',
            'low': '#00FF00'
        }

        message = {
            'attachments': [{
                'color': severity_colors.get(alert.get('severity', 'medium').lower(), '#808080'),
                'title': f"Security Alert: {alert.get('title', 'Unknown Alert')}",
                'fields': [
                    {
                        'title': 'Severity',
                        'value': alert.get('severity', 'Unknown'),
                        'short': True
                    },
                    {
                        'title': 'Source',
                        'value': alert.get('source', 'Unknown'),
                        'short': True
                    },
                    {
                        'title': 'Description',
                        'value': alert.get('description', 'No description provided'),
                        'short': False
                    },
                    {
                        'title': 'Impact',
                        'value': alert.get('impact', 'No impact assessment'),
                        'short': False
                    },
                    {
                        'title': 'Recommendations',
                        'value': '\n'.join(alert.get('recommendations', ['No recommendations'])),
                        'short': False
                    }
                ],
                'footer': f"AluhaSOC | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                'ts': int(datetime.now().timestamp())
            }]
        }

        response = requests.post(
            self.slack_webhook_url,
            json=message
        )
        response.raise_for_status()

    def _send_email_alert(self, alert: Dict[str, Any]):
        """Send alert via email"""
        if not all([self.smtp_config['username'], self.smtp_config['password']]):
            raise ValueError("SMTP credentials not configured")

        msg = MIMEMultipart()
        msg['From'] = self.smtp_config['from_email']
        msg['To'] = alert.get('recipients', self.config['default_recipients'])
        msg['Subject'] = f"Security Alert: {alert.get('title', 'Unknown Alert')}"

        body = f"""
        Security Alert Details:
        
        Title: {alert.get('title', 'Unknown Alert')}
        Severity: {alert.get('severity', 'Unknown')}
        Source: {alert.get('source', 'Unknown')}
        Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        Description:
        {alert.get('description', 'No description provided')}
        
        Impact:
        {alert.get('impact', 'No impact assessment')}
        
        Recommendations:
        {chr(10).join(alert.get('recommendations', ['No recommendations']))}
        
        Additional Information:
        {alert.get('additional_info', 'No additional information')}
        """

        msg.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port']) as server:
                server.starttls()
                server.login(self.smtp_config['username'], self.smtp_config['password'])
                server.send_message(msg)
        except Exception as e:
            print(f"Error sending email: {e}")
            raise

    def format_incident_notification(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Format incident details for notification"""
        return {
            'title': f"Security Incident: {incident.get('id', 'Unknown')}",
            'severity': incident.get('severity', 'medium'),
            'source': incident.get('source', 'Unknown'),
            'description': incident.get('description', 'No description provided'),
            'impact': incident.get('impact', 'No impact assessment'),
            'recommendations': incident.get('remediation', ['No recommendations']),
            'additional_info': {
                'timeline': incident.get('timeline', []),
                'root_cause': incident.get('root_cause', 'Unknown'),
                'affected_systems': incident.get('affected_systems', []),
                'status': incident.get('status', 'Unknown')
            }
        } 