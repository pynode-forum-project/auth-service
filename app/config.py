import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration"""
    
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key')
    DEBUG = os.getenv('FLASK_ENV', 'development') == 'development'
    
    # JWT settings
    JWT_SECRET = os.getenv('JWT_SECRET', 'your-super-secret-jwt-key-change-in-production')
    JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', 24))
    
    # Service URLs
    USER_SERVICE_URL = os.getenv('USER_SERVICE_URL', 'http://localhost:5001')
    
    # RabbitMQ settings
    RABBITMQ_URL = os.getenv('RABBITMQ_URL', 'amqp://guest:guest@localhost:5672')
    
    # Email verification settings
    VERIFICATION_TOKEN_HOURS = int(os.getenv('VERIFICATION_TOKEN_HOURS', 3))
