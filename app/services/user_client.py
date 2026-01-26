import requests
import os
import logging

logger = logging.getLogger(__name__)


class UserClient:
    """HTTP client for User Service"""
    
    def __init__(self):
        self.base_url = os.getenv('USER_SERVICE_URL', 'http://localhost:5001')
        self.timeout = 10
    
    def get_user_by_email(self, email: str) -> dict:
        """Get user by email address"""
        try:
            response = requests.get(
                f'{self.base_url}/internal/users/email/{email}',
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                logger.error(f'Error getting user by email: {response.text}')
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f'Request to user service failed: {str(e)}')
            return None
    
    def get_user_by_id(self, user_id: int) -> dict:
        """Get user by ID"""
        try:
            response = requests.get(
                f'{self.base_url}/internal/users/{user_id}',
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                logger.error(f'Error getting user by id: {response.text}')
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f'Request to user service failed: {str(e)}')
            return None
    
    def create_user(self, user_data: dict) -> dict:
        """Create a new user"""
        try:
            response = requests.post(
                f'{self.base_url}/internal/users',
                json=user_data,
                timeout=self.timeout
            )
            
            if response.status_code in [200, 201]:
                return response.json()
            else:
                logger.error(f'Error creating user: {response.text}')
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f'Request to user service failed: {str(e)}')
            return None
    
    def verify_email(self, email: str, token: str) -> dict:
        """Verify user email with token"""
        try:
            response = requests.post(
                f'{self.base_url}/internal/users/verify-email',
                json={'email': email, 'token': token},
                timeout=self.timeout
            )
            
            return response.json()
                
        except requests.exceptions.RequestException as e:
            logger.error(f'Request to user service failed: {str(e)}')
            return {'success': False, 'message': 'Service unavailable'}
    
    def update_verification_token(self, user_id: int, token: str, expires_at: str) -> bool:
        """Update user's verification token"""
        try:
            response = requests.put(
                f'{self.base_url}/internal/users/{user_id}/verification-token',
                json={'token': token, 'expiresAt': expires_at},
                timeout=self.timeout
            )
            
            return response.status_code == 200
                
        except requests.exceptions.RequestException as e:
            logger.error(f'Request to user service failed: {str(e)}')
            return False
    
    def get_valid_verification_token(self, user_id: int) -> dict:
        """Get valid verification token if exists and not expired"""
        try:
            response = requests.get(
                f'{self.base_url}/internal/users/{user_id}/verification-token/valid',
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f'Error getting valid token: {response.text}')
                return {'token': None, 'expiresAt': None}
                
        except requests.exceptions.RequestException as e:
            logger.error(f'Request to user service failed: {str(e)}')
            return {'token': None, 'expiresAt': None}
