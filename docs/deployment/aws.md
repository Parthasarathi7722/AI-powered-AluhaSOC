# AWS Deployment Guide

This guide provides detailed instructions for deploying the AI-powered AluhaSOC on AWS infrastructure.

## Prerequisites

- AWS Account with administrative access
- AWS CLI installed and configured
- Docker and Docker Compose installed
- kubectl installed (for EKS deployment)

## Infrastructure Components

The deployment consists of the following AWS services:
- ECS/EKS for container orchestration
- RDS for PostgreSQL database
- ElastiCache for Redis
- S3 for model storage
- CloudWatch for logging
- IAM for authentication and authorization

## 1. IAM Setup

1. Create an IAM role for the application:
```bash
aws iam create-role --role-name aluhasoc-app-role --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ecs-tasks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}'
```

2. Attach necessary policies:
```bash
# Security services access
aws iam attach-role-policy --role-name aluhasoc-app-role --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam attach-role-policy --role-name aluhasoc-app-role --policy-arn arn:aws:iam::aws:policy/AmazonGuardDutyFullAccess

# S3 access for model storage
aws iam attach-role-policy --role-name aluhasoc-app-role --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess

# CloudWatch access for logging
aws iam attach-role-policy --role-name aluhasoc-app-role --policy-arn arn:aws:iam::aws:policy/CloudWatchLogsFullAccess
```

## 2. Security Services Setup

1. Enable AWS Security Hub:
```bash
aws securityhub enable-security-hub
```

2. Enable AWS GuardDuty:
```bash
aws guardduty create-detector --enable
```

3. Enable AWS CloudTrail:
```bash
aws cloudtrail create-trail --name aluhasoc-trail --s3-bucket-name your-bucket-name
aws cloudtrail start-logging --name aluhasoc-trail
```

## 3. Database Setup

1. Create RDS instance:
```bash
aws rds create-db-instance \
  --db-instance-identifier aluhasoc-db \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --master-username admin \
  --master-user-password your-password \
  --allocated-storage 20
```

2. Create ElastiCache cluster:
```bash
aws elasticache create-cache-cluster \
  --cache-cluster-id aluhasoc-redis \
  --engine redis \
  --cache-node-type cache.t3.micro \
  --num-cache-nodes 1
```

## 4. ECS Deployment

1. Create ECS cluster:
```bash
aws ecs create-cluster --cluster-name aluhasoc-cluster
```

2. Create task definition:
```json
{
  "family": "aluhasoc",
  "containerDefinitions": [
    {
      "name": "app",
      "image": "your-ecr-repo/aluhasoc:latest",
      "cpu": 256,
      "memory": 512,
      "essential": true,
      "portMappings": [
        {
          "containerPort": 8080,
          "hostPort": 8080
        }
      ],
      "environment": [
        {
          "name": "AWS_ACCESS_KEY_ID",
          "value": "your-access-key"
        },
        {
          "name": "AWS_SECRET_ACCESS_KEY",
          "value": "your-secret-key"
        }
      ]
    }
  ],
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "256",
  "memory": "512"
}
```

3. Create service:
```bash
aws ecs create-service \
  --cluster aluhasoc-cluster \
  --service-name aluhasoc-service \
  --task-definition aluhasoc:1 \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxxxx],securityGroups=[sg-xxxxx]}"
```

## 5. EKS Deployment (Alternative)

1. Create EKS cluster:
```bash
eksctl create cluster \
  --name aluhasoc-cluster \
  --region us-west-2 \
  --node-type t3.medium \
  --nodes 2 \
  --nodes-min 2 \
  --nodes-max 4
```

2. Deploy using Helm:
```bash
helm install aluhasoc ./helm/aluhasoc \
  --set aws.accessKeyId=your-access-key \
  --set aws.secretAccessKey=your-secret-key \
  --set postgres.host=your-rds-endpoint \
  --set redis.host=your-redis-endpoint
```

## 6. Monitoring Setup

1. Create CloudWatch dashboard:
```bash
aws cloudwatch put-dashboard \
  --dashboard-name AluhaSOC \
  --dashboard-body '{
    "widgets": [
      {
        "type": "metric",
        "properties": {
          "metrics": [
            ["AWS/ECS", "CPUUtilization", "ServiceName", "aluhasoc-service"],
            ["AWS/ECS", "MemoryUtilization", "ServiceName", "aluhasoc-service"]
          ],
          "period": 300,
          "stat": "Average",
          "region": "us-west-2",
          "title": "ECS Metrics"
        }
      }
    ]
  }'
```

2. Set up alarms:
```bash
aws cloudwatch put-metric-alarm \
  --alarm-name aluhasoc-cpu-high \
  --alarm-description "CPU utilization is high" \
  --metric-name CPUUtilization \
  --namespace AWS/ECS \
  --statistic Average \
  --period 300 \
  --threshold 80 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --alarm-actions arn:aws:sns:region:account-id:your-topic
```

## 7. Security Configuration

1. Configure VPC endpoints for AWS services:
```bash
aws ec2 create-vpc-endpoint \
  --vpc-id vpc-xxxxx \
  --service-name com.amazonaws.us-west-2.securityhub \
  --vpc-endpoint-type Interface \
  --subnet-ids subnet-xxxxx subnet-yyyyy \
  --security-group-ids sg-xxxxx
```

2. Set up WAF rules:
```bash
aws wafv2 create-web-acl \
  --name aluhasoc-waf \
  --scope REGIONAL \
  --default-action Block={} \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=aluhasoc-waf
```

## 8. Backup and Recovery

1. Configure RDS backups:
```bash
aws rds modify-db-instance \
  --db-instance-identifier aluhasoc-db \
  --backup-retention-period 7 \
  --preferred-backup-window 03:00-04:00
```

2. Set up S3 versioning for model storage:
```bash
aws s3api put-bucket-versioning \
  --bucket your-model-bucket \
  --versioning-configuration Status=Enabled
```

## Troubleshooting

Common issues and solutions:

1. **ECS Task Failures**
   - Check CloudWatch logs
   - Verify IAM roles and permissions
   - Ensure environment variables are correctly set

2. **Database Connection Issues**
   - Verify security group rules
   - Check RDS endpoint configuration
   - Ensure correct credentials are used

3. **Security Service Access**
   - Verify IAM policies
   - Check VPC endpoint configuration
   - Ensure correct regions are configured

## Maintenance

Regular maintenance tasks:

1. Update ECS task definition:
```bash
aws ecs register-task-definition --cli-input-json file://task-definition.json
```

2. Scale ECS service:
```bash
aws ecs update-service --cluster aluhasoc-cluster --service aluhasoc-service --desired-count 2
```

3. Rotate credentials:
```bash
aws iam create-access-key --user-name aluhasoc-user
aws iam delete-access-key --user-name aluhasoc-user --access-key-id AKIAXXXXXXXXXXXXXXXX
``` 