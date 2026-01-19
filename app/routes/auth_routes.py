# TODO: Add login() and verify_token() functions when implementing FP-13/FP-14
from flask import Blueprint, request, jsonify
import bcrypt
from app.utils.user_service_client import UserServiceClient

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    POST /auth/register
    Register a new user
    
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
            return jsonify({'error': 'Request body is required'}), 400
        
        first_name = data.get('firstName')
        last_name = data.get('lastName')
        email = data.get('email')
        password = data.get('password')
        
        # Validate required fields
        if not all([first_name, last_name, email, password]):
            return jsonify({'error': 'All fields (firstName, lastName, email, password) are required'}), 400
        
        # Validate email format (basic check)
        if '@' not in email:
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Validate password length
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters long'}), 400
        
        # Hash password using bcrypt before sending to user-service
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create user via user-service (password is already hashed)
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
    
    except Exception as e:
        # Error handlers will catch specific exceptions
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500
