# API Documentation

## Overview

The AI-powered AluhaSOC provides a RESTful API for interacting with the security operations center. The API is available at `http://localhost:8080/api/v1` by default.

## Authentication

All API endpoints require authentication using JWT tokens. Include the token in the Authorization header:

```http
Authorization: Bearer <your_jwt_token>
```

## Endpoints

### Log Collection

#### GET /api/v1/logs
Retrieve logs from configured sources.

**Query Parameters:**
- `source` (string, optional): Filter by log source (aws, azure, gcp, splunk, wazuh)
- `start_time` (string, optional): ISO 8601 timestamp for start time
- `end_time` (string, optional): ISO 8601 timestamp for end time
- `severity` (string, optional): Filter by severity (critical, high, medium, low)
- `limit` (integer, optional): Maximum number of logs to return (default: 100)

**Response:**
```json
{
  "logs": [
    {
      "id": "string",
      "timestamp": "string",
      "source": "string",
      "severity": "string",
      "event_type": "string",
      "source_ip": "string",
      "action": "string",
      "status": "string",
      "message": "string",
      "raw": "string"
    }
  ],
  "total": 0,
  "page": 0,
  "size": 0
}
```

#### POST /api/v1/logs/analyze
Submit logs for analysis.

**Request Body:**
```json
{
  "log_ids": ["string"],
  "analysis_type": "string",
  "options": {
    "include_context": true,
    "include_recommendations": true
  }
}
```

**Response:**
```json
{
  "analysis_id": "string",
  "status": "string",
  "results": {
    "summary": "string",
    "threats": [],
    "recommendations": [],
    "context": {}
  }
}
```

### Configuration

#### GET /api/v1/config
Retrieve current configuration.

**Response:**
```json
{
  "log_sources": {
    "aws": {},
    "azure": {},
    "gcp": {},
    "splunk": {},
    "wazuh": {}
  },
  "llm": {},
  "notifications": {}
}
```

#### PUT /api/v1/config
Update configuration.

**Request Body:**
```json
{
  "log_sources": {
    "aws": {
      "regions": ["string"],
      "services": ["string"]
    }
  },
  "llm": {
    "model": "string",
    "quantization": "string",
    "batch_size": 0
  }
}
```

### Notifications

#### POST /api/v1/notifications
Send a notification.

**Request Body:**
```json
{
  "channel": "string",
  "message": "string",
  "severity": "string",
  "metadata": {}
}
```

#### GET /api/v1/notifications/templates
List notification templates.

**Response:**
```json
{
  "templates": [
    {
      "id": "string",
      "name": "string",
      "channel": "string",
      "template": "string",
      "variables": ["string"]
    }
  ]
}
```

### Analysis

#### GET /api/v1/analysis/rules
List analysis rules.

**Response:**
```json
{
  "rules": [
    {
      "id": "string",
      "name": "string",
      "description": "string",
      "severity": "string",
      "conditions": [],
      "actions": []
    }
  ]
}
```

#### POST /api/v1/analysis/rules
Create a new analysis rule.

**Request Body:**
```json
{
  "name": "string",
  "description": "string",
  "severity": "string",
  "conditions": [
    {
      "field": "string",
      "operator": "string",
      "value": "string"
    }
  ],
  "actions": [
    {
      "type": "string",
      "parameters": {}
    }
  ]
}
```

## Error Responses

All endpoints may return the following error responses:

```json
{
  "error": {
    "code": "string",
    "message": "string",
    "details": {}
  }
}
```

Common error codes:
- `400`: Bad Request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `429`: Too Many Requests
- `500`: Internal Server Error

## Rate Limiting

API requests are limited to:
- 100 requests per minute for authenticated users
- 20 requests per minute for unauthenticated users

Rate limit headers are included in all responses:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
``` 