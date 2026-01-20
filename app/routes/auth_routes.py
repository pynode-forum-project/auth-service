from flask import Blueprint, request, jsonify
import bcrypt
from app.utils.user_service_client import UserServiceClient
from app.utils.jwt_utils import generate_token
from app.utils.exceptions import (
    InvalidCredentialsError,
    UserAlreadyExistsError,
    UserServiceError,
    ValidationError
)

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Request Body:
        {
            "firstName": "John",
            "lastName": "Doe",
            "email": "user@example.com",
            "password": "password123"
        }
    
    Response:
        {
            "message": "Registration successful",
            "user_id": "uuid-string"
        }
    """
    try:
        data = request.get_json()
        
        if not data:
            raise ValidationError("Request body is required")
        
        first_name = data.get('firstName')
        last_name = data.get('lastName')
        email = data.get('email')
        password = data.get('password')
        
        if not all([first_name, last_name, email, password]):
            raise ValidationError("All fields (firstName, lastName, email, password) are required")
        
        if '@' not in email:
            raise ValidationError("Invalid email format")
        
        if len(password) < 6:
            raise ValidationError("Password must be at least 6 characters long")
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        user_data = UserServiceClient.create_user(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_password
        )
        
        return jsonify({
            'message': 'Registration successful',
            'user_id': user_data['userId']
        }), 201
    
    except (ValidationError, UserAlreadyExistsError, UserServiceError):
        raise
    except Exception as e:
        from flask import current_app
        current_app.logger.error(f"Registration failed: {str(e)}", exc_info=True)
        raise UserServiceError("Registration failed. Please try again later.")

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Request Body:
        {
            "email": "user@example.com",
            "password": "password123"
        }
    
    Response:
        {
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "user_id": "uuid-string",
            "user_type": "normal_user",
            "isActive": true
        }
    """
    try:
        data = request.get_json()
        
        if not data:
            raise InvalidCredentialsError("Request body is required")
        
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            raise InvalidCredentialsError("Email and password are required")
        
        user_data = UserServiceClient.verify_user_credentials(email, password)
        
        token = generate_token(
            user_id=user_data['userId'],
            user_type=user_data.get('userType', 'normal_user'),
            is_active=user_data.get('isActive', False)
        )
        
        return jsonify({
            'token': token,
            'user_id': user_data['userId'],
            'user_type': user_data.get('userType', 'normal_user'),
            'isActive': user_data.get('isActive', False)
        }), 200
    
    except (InvalidCredentialsError, UserServiceError):
        raise
    except Exception as e:
        from flask import current_app
        current_app.logger.error(f"Login failed: {str(e)}", exc_info=True)
        raise UserServiceError("Login failed. Please try again later.")
