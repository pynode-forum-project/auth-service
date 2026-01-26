import pika
import json
import os
import logging

logger = logging.getLogger(__name__)


class MessageQueue:
    """RabbitMQ message queue client"""
    
    def __init__(self):
        self.rabbitmq_url = os.getenv('RABBITMQ_URL', 'amqp://guest:guest@localhost:5672')
        self.connection = None
        self.channel = None
    
    def _get_connection(self):
        """Get or create RabbitMQ connection"""
        if self.connection is None or self.connection.is_closed:
            try:
                params = pika.URLParameters(self.rabbitmq_url)
                self.connection = pika.BlockingConnection(params)
                self.channel = self.connection.channel()
                
                # Declare the email queue
                self.channel.queue_declare(queue='email.verification', durable=True)
                self.channel.queue_declare(queue='email.notification', durable=True)
                
            except Exception as e:
                logger.error(f'Failed to connect to RabbitMQ: {str(e)}')
                raise
        
        return self.channel
    
    def send_verification_email(self, email: str, first_name: str, token: str):
        """Send verification email via RabbitMQ"""
        try:
            channel = self._get_connection()
            
            message = {
                'type': 'verification',
                'email': email,
                'firstName': first_name,
                'token': token
            }
            
            channel.basic_publish(
                exchange='',
                routing_key='email.verification',
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # make message persistent
                    content_type='application/json'
                )
            )
            
            logger.info(f'Verification email queued for {email}')
            
        except Exception as e:
            logger.error(f'Failed to queue verification email: {str(e)}')
            # Don't raise - email is not critical for registration
    
    def send_notification_email(self, email: str, subject: str, message: str):
        """Send notification email via RabbitMQ"""
        try:
            channel = self._get_connection()
            
            email_message = {
                'type': 'notification',
                'email': email,
                'subject': subject,
                'message': message
            }
            
            channel.basic_publish(
                exchange='',
                routing_key='email.notification',
                body=json.dumps(email_message),
                properties=pika.BasicProperties(
                    delivery_mode=2,
                    content_type='application/json'
                )
            )
            
            logger.info(f'Notification email queued for {email}')
            
        except Exception as e:
            logger.error(f'Failed to queue notification email: {str(e)}')
    
    def close(self):
        """Close RabbitMQ connection"""
        if self.connection and not self.connection.is_closed:
            self.connection.close()
