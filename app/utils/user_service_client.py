# user_service_client.py
# Client for communicating with user-service
# TODO: Add verify_user_credentials() and get_user_by_id() methods when implementing FP-13
# See .backup/user_service_client_login.py.backup for reference

import requests
from flask import current_app
from app.utils.exceptions import (
    UserNotFoundError,
    UserAlreadyExistsError,
    UserServiceError
)

class UserServiceClient:
    """Client for interacting with user-service"""
    
    @staticmethod
    def _get_base_url():
        """Get the base URL for user service"""
        return current_app.config['USER_SERVICE_URL']
    
    @staticmethod
    def create_user(first_name, last_name, email, password):
        """
        Create a new user via user-service
        
        Args:
            first_name: User's first name
            last_name: User's last name
            email: User's email
            password: User's password
        
        Returns:
            dict: Created user data
        
        Raises:
            UserAlreadyExistsError: If user with email already exists
            UserServiceError: If communication with user-service fails
        """
        try:
            url = f"{UserServiceClient._get_base_url()}/internal/users"
            response = requests.post(
                url,
                json={
                    'firstName': first_name,
                    'lastName': last_name,
                    'email': email,
                    'password': password
                },
                timeout=5
            )
            
            if response.status_code == 201:
                return response.json()
            elif response.status_code == 409:
                raise UserAlreadyExistsError("User with this email already exists")
            else:
                raise UserServiceError(f"User service returned status {response.status_code}")
        
        except requests.exceptions.RequestException as e:
            raise UserServiceError(f"Failed to communicate with user service: {str(e)}")
