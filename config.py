# Configuration for auth service
# TODO: Add JWT Configuration when implementing FP-13/FP-14

import os

class Config:
    # TODO: Add JWT Configuration for FP-13/FP-14
    
    # User Service Configuration
    USER_SERVICE_URL = os.getenv('USER_SERVICE_URL', 'http://user-service:5000')
    
    # RabbitMQ Configuration (for email service)
    RABBITMQ_HOST = os.getenv('RABBITMQ_HOST', 'rabbitmq')
    RABBITMQ_PORT = int(os.getenv('RABBITMQ_PORT', '5672'))
    RABBITMQ_USER = os.getenv('RABBITMQ_USER', 'guest')
    RABBITMQ_PASSWORD = os.getenv('RABBITMQ_PASSWORD', 'guest')
    
    # Email Queue Name
    EMAIL_QUEUE = os.getenv('EMAIL_QUEUE', 'email_queue')
