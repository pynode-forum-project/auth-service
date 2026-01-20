import requests
from flask import current_app
from app.utils.exceptions import (
    InvalidCredentialsError,
    UserNotFoundError,
    UserAlreadyExistsError,
    UserServiceError
)

class UserServiceClient:
    @staticmethod
    def _get_base_url():
        return current_app.config['USER_SERVICE_URL']
    
    @staticmethod
    def create_user(first_name, last_name, email, password):
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
    
    @staticmethod
    def verify_user_credentials(email, password):
        try:
            url = f"{UserServiceClient._get_base_url()}/internal/users/verify"
            response = requests.post(
                url,
                json={'email': email, 'password': password},
                timeout=5
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                raise InvalidCredentialsError("Invalid email or password")
            elif response.status_code == 404:
                raise UserNotFoundError("User not found")
            else:
                raise UserServiceError(f"User service returned status {response.status_code}")
        
        except (InvalidCredentialsError, UserNotFoundError, UserServiceError):
            raise
        except requests.exceptions.RequestException as e:
            raise UserServiceError(f"Failed to communicate with user service: {str(e)}")
