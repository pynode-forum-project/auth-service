import jwt
import bcrypt
import secrets
from datetime import datetime, timedelta
from flask import current_app
import os


class AuthService:
    """Service for authentication operations"""
    
    def __init__(self):
        self.jwt_secret = os.getenv('JWT_SECRET', 'your-super-secret-jwt-key-change-in-production')
        self.jwt_expiration_hours = int(os.getenv('JWT_EXPIRATION_HOURS', 24))
        self.verification_token_hours = int(os.getenv('VERIFICATION_TOKEN_HOURS', 3))
    
    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except Exception:
            return False
    
    def generate_token(self, user: dict) -> str:
        """Generate JWT token for user"""
        payload = {
            'userId': user.get('user_id'),
            'email': user.get('email'),
            'type': user.get('type'),
            'emailVerified': user.get('email_verified', False),
            'active': user.get('active', True),
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=self.jwt_expiration_hours)
        }
        
        token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')
        return token
    
    def decode_token(self, token: str, verify_exp: bool = True) -> dict:
        """Decode and verify JWT token"""
        options = {'verify_exp': verify_exp}
        return jwt.decode(token, self.jwt_secret, algorithms=['HS256'], options=options)
    
    def generate_verification_token(self) -> str:
        """Generate a 6-digit verification code"""
        return str(secrets.randbelow(900000) + 100000)
    
    def get_token_expiry(self) -> datetime:
        """Get the expiry time for verification token"""
        return datetime.utcnow() + timedelta(hours=self.verification_token_hours)
