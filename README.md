# AI-powered AluhaSOC

An open-source, LLM-powered Security Operations Center (SOC) automation suite that provides real-time security analysis, incident response, and historical investigation capabilities.

## Features

- **Modular Log Collection**
  - Support for multiple log sources (Splunk, Wazuh, AWS, Azure, GCP)
  - Extensible architecture for adding new log sources
  - Configurable log parsing and normalization

- **Real-time Analysis**
  - LLM-powered security event analysis
  - Optimized inference with quantization and batching
  - Customizable alerting rules and thresholds

- **Notification System**
  - Multi-channel alerting (Slack, Email)
  - Rich context enrichment
  - Configurable notification templates

- **Historical Analysis**
  - Long-term storage of security events
  - LLM-powered investigation workflows
  - Advanced querying capabilities

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│  Log Sources    │────▶│  Log Agents  │────▶│   RabbitMQ      │
│  (Splunk, etc.) │     │              │     │   Message Bus   │
└─────────────────┘     └──────────────┘     └────────┬────────┘
                                                      │
┌─────────────────┐     ┌──────────────┐     ┌───────▼────────┐
│  Notification   │◀────│  Analysis    │◀────│   LLM Engine   │
│  System         │     │  Agent       │     │                │
└─────────────────┘     └──────────────┘     └────────┬────────┘
                                                      │
┌─────────────────┐     ┌──────────────┐     ┌───────▼────────┐
│  Investigation  │◀────│  Storage     │◀────│   Fine-tuning  │
│  Workflow       │     │  Layer       │     │   Pipeline     │
└─────────────────┘     └──────────────┘     └─────────────────┘
```

## Prerequisites

- Docker and Docker Compose
- Python 3.9+
- RabbitMQ
- CUDA-capable GPU (optional, for GPU acceleration)
- Cloud Provider Accounts (AWS, Azure, GCP)
- Splunk Enterprise (optional)
- Wazuh Manager (optional)

## Quick Start

1. Clone the repository:
```bash
git clone https://github.com/yourusername/AI-powered-AluhaSOC.git
cd AI-powered-AluhaSOC
```

2. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Start the services:
```bash
docker-compose up -d
```

4. Access the web interface at `http://localhost:8080`

## Project Structure

```
.
├── agents/                 # Log collection agents
│   ├── splunk/            # Splunk agent
│   ├── wazuh/             # Wazuh agent
│   ├── aws/               # AWS agent
│   ├── azure/             # Azure agent
│   └── gcp/               # GCP agent
├── analysis/              # Analysis engine
│   ├── llm/               # LLM inference code
│   └── rules/             # Analysis rules
├── storage/               # Storage layer
│   ├── models/            # Database models
│   └── migrations/        # Database migrations
├── notifications/         # Notification system
├── web/                   # Web interface
├── docker/                # Docker configuration
├── docs/                  # Documentation
└── tests/                 # Test suite
```

## Configuration

### Log Sources
Configure log sources in `config/log_sources.yaml`:
```yaml
splunk:
  host: splunk.example.com
  port: 8089
  username: admin
  password: ${SPLUNK_PASSWORD}

wazuh:
  host: wazuh.example.com
  port: 1514
  api_key: ${WAZUH_API_KEY}

aws:
  regions: ['us-east-1']
  services: ['CloudTrail', 'GuardDuty', 'SecurityHub']

azure:
  subscription_id: ${AZURE_SUBSCRIPTION_ID}
  tenant_id: ${AZURE_TENANT_ID}
  services: ['SecurityCenter', 'Monitor']

gcp:
  project_id: ${GCP_PROJECT_ID}
  organization_id: ${GCP_ORG_ID}
  services: ['SecurityCommandCenter', 'CloudMonitoring', 'CloudLogging']
```

### LLM Configuration
Configure LLM settings in `config/llm.yaml`:
```yaml
model:
  name: llama2-7b
  quantization: int8
  batch_size: 32
  max_length: 512
  gpu_memory_utilization: 0.9
  tensor_parallel_size: 1
```

## Deployment Guides

### AWS Deployment
1. Create an IAM role with necessary permissions
2. Configure AWS credentials in .env
3. Enable required services (CloudTrail, GuardDuty, SecurityHub)
4. Deploy using AWS ECS or EKS

### Azure Deployment
1. Create a service principal
2. Configure Azure credentials in .env
3. Enable required services (Security Center, Monitor)
4. Deploy using Azure Container Apps or AKS

### GCP Deployment
1. Create a service account with necessary roles
2. Configure GCP credentials in .env
3. Enable required APIs (Security Command Center, Cloud Monitoring)
4. Deploy using Google Cloud Run or GKE

## GPU Support

The system supports GPU acceleration for LLM inference. To enable:

1. Install NVIDIA Container Toolkit
2. Set CUDA_VISIBLE_DEVICES in .env
3. Configure GPU resources in docker-compose.yml
4. Set appropriate tensor_parallel_size in llm.yaml

## Development

### Adding New Log Sources
1. Create a new agent in `agents/`
2. Implement the required interfaces
3. Add configuration templates
4. Update documentation

### Fine-tuning the LLM
1. Prepare your security dataset
2. Configure fine-tuning parameters
3. Run the fine-tuning pipeline
4. Evaluate and deploy the model

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers. 