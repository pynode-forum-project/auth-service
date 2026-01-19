# email_queue.py
# Utility for sending messages to RabbitMQ email queue
# NOTE: Currently not used in register/login endpoints.
# Email verification will be handled separately in user profile or other services.
# This file is kept for future use when email functionality is needed.

import pika
import json
from flask import current_app
from app.utils.exceptions import UserServiceError

class EmailQueueClient:
    """Client for sending email messages to RabbitMQ"""
    
    @staticmethod
    def _get_connection():
        """Create RabbitMQ connection"""
        try:
            credentials = pika.PlainCredentials(
                current_app.config['RABBITMQ_USER'],
                current_app.config['RABBITMQ_PASSWORD']
            )
            parameters = pika.ConnectionParameters(
                host=current_app.config['RABBITMQ_HOST'],
                port=current_app.config['RABBITMQ_PORT'],
                credentials=credentials
            )
            return pika.BlockingConnection(parameters)
        except Exception as e:
            raise UserServiceError(f"Failed to connect to RabbitMQ: {str(e)}")
    
    @staticmethod
    def send_verification_email(email, verification_code):
        """
        Send verification email message to RabbitMQ queue
        
        Args:
            email: Recipient email address
            verification_code: 6-digit verification code or token
        """
        try:
            connection = EmailQueueClient._get_connection()
            channel = connection.channel()
            
            queue_name = current_app.config['EMAIL_QUEUE']
            channel.queue_declare(queue=queue_name, durable=True)
            
            message = {
                'type': 'verification',
                'email': email,
                'verification_code': verification_code
            }
            
            channel.basic_publish(
                exchange='',
                routing_key=queue_name,
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2,  # Make message persistent
                )
            )
            
            connection.close()
        except Exception as e:
            # Log error but don't fail registration
            current_app.logger.error(f"Failed to send email to queue: {str(e)}")
