import pika
import json
from typing import Callable, Dict, Any
import os
from datetime import datetime

class MessageBus:
    def __init__(self, host: str = 'localhost', port: int = 5672):
        self.connection = None
        self.channel = None
        self.host = host
        self.port = port
        self.queues = {
            'logs': 'security_logs',
            'analysis': 'security_analysis',
            'alerts': 'security_alerts',
            'investigations': 'security_investigations'
        }
        self.connect()

    def connect(self):
        """Establish connection to RabbitMQ"""
        try:
            credentials = pika.PlainCredentials(
                os.getenv('RABBITMQ_USER', 'guest'),
                os.getenv('RABBITMQ_PASSWORD', 'guest')
            )
            parameters = pika.ConnectionParameters(
                host=self.host,
                port=self.port,
                credentials=credentials
            )
            self.connection = pika.BlockingConnection(parameters)
            self.channel = self.connection.channel()
            self._setup_queues()
        except Exception as e:
            print(f"Failed to connect to RabbitMQ: {e}")
            raise

    def _setup_queues(self):
        """Setup required queues"""
        for queue in self.queues.values():
            self.channel.queue_declare(queue=queue, durable=True)

    def publish(self, queue: str, message: Dict[str, Any]):
        """Publish a message to a queue"""
        try:
            if queue not in self.queues.values():
                raise ValueError(f"Invalid queue: {queue}")

            message['timestamp'] = datetime.now().isoformat()
            self.channel.basic_publish(
                exchange='',
                routing_key=queue,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # make message persistent
                )
            )
        except Exception as e:
            print(f"Failed to publish message: {e}")
            raise

    def consume(self, queue: str, callback: Callable[[Dict[str, Any]], None]):
        """Consume messages from a queue"""
        try:
            if queue not in self.queues.values():
                raise ValueError(f"Invalid queue: {queue}")

            def _callback(ch, method, properties, body):
                try:
                    message = json.loads(body)
                    callback(message)
                    ch.basic_ack(delivery_tag=method.delivery_tag)
                except Exception as e:
                    print(f"Error processing message: {e}")
                    ch.basic_nack(delivery_tag=method.delivery_tag)

            self.channel.basic_qos(prefetch_count=1)
            self.channel.basic_consume(
                queue=queue,
                on_message_callback=_callback
            )
            self.channel.start_consuming()
        except Exception as e:
            print(f"Failed to consume messages: {e}")
            raise

    def close(self):
        """Close the connection"""
        if self.connection and not self.connection.is_closed:
            self.connection.close() 