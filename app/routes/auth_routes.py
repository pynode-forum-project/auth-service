from flask import request, jsonify, current_app
from app.routes import auth_bp
from app.services.auth_service import AuthService
from app.services.user_client import UserClient
from app.services.message_queue import MessageQueue
from app.utils.validators import validate_login, validate_register
from app.utils.decorators import handle_exceptions

auth_service = AuthService()
user_client = UserClient()
message_queue = MessageQueue()


@auth_bp.route('/login', methods=['POST'])
@handle_exceptions
def login():
    """Authenticate user and return JWT token"""
    data = request.get_json()
    
    # Validate input
    errors = validate_login(data)
    if errors:
        return jsonify({'error': 'Validation failed', 'details': errors}), 400
    
    email = data.get('email')
    password = data.get('password')
    
    # Get user from user service
    user = user_client.get_user_by_email(email)
    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401
    
    # Check if user is banned
    if not user.get('active'):
        return jsonify({'error': 'Account has been banned. Please contact admin.'}), 403
    
    # Verify password
    if not auth_service.verify_password(password, user.get('password')):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    # Generate JWT token
    token = auth_service.generate_token(user)
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'userId': user.get('user_id'),
            'email': user.get('email'),
            'firstName': user.get('first_name'),
            'lastName': user.get('last_name'),
            'pendingEmail': user.get('pending_email'),
            'type': user.get('type'),
            'active': user.get('active', True),
            'profileImageUrl': user.get('profile_image_url')
        }
    }), 200


@auth_bp.route('/register', methods=['POST'])
@handle_exceptions
def register():
    """Register a new user"""
    data = request.get_json()
    
    # Validate input
    errors = validate_register(data)
    if errors:
        return jsonify({'error': 'Validation failed', 'details': errors}), 400
    
    # Check if email already exists
    existing_user = user_client.get_user_by_email(data.get('email'))
    pending_user = user_client.get_user_by_pending_email(data.get('email'))
    if existing_user:
        return jsonify({'error': 'Email already registered'}), 409
    if pending_user:
        return jsonify({'error': 'Email already registered'}), 409
    
    # Hash password
    hashed_password = auth_service.hash_password(data.get('password'))
    
    # Generate verification token
    verification_token = auth_service.generate_verification_token()
    token_expires = auth_service.get_token_expiry()
    
    # Create user via user service
    user_data = {
        'firstName': data.get('firstName'),
        'lastName': data.get('lastName'),
        'email': data.get('email'),
        'password': hashed_password,
        'verificationToken': verification_token,
        'tokenExpiresAt': token_expires.isoformat()
    }
    
    new_user = user_client.create_user(user_data)
    if not new_user:
        return jsonify({'error': 'Failed to create user'}), 500
    
    # Send verification email via RabbitMQ
    message_queue.send_verification_email(
        email=data.get('email'),
        first_name=data.get('firstName'),
        token=verification_token
    )
    
    # Generate JWT token
    token = auth_service.generate_token(new_user)
    
    return jsonify({
        'message': 'Registration successful. Please check your email to verify your account.',
        'token': token,
        'user': {
            'userId': new_user.get('user_id'),
            'email': new_user.get('email'),
            'firstName': new_user.get('first_name'),
            'lastName': new_user.get('last_name'),
            'pendingEmail': new_user.get('pending_email'),
            'type': new_user.get('type')
        }
    }), 201


@auth_bp.route('/verify-email', methods=['POST'])
@handle_exceptions
def verify_email():
    """Verify user email with token"""
    data = request.get_json()
    token = data.get('token')
    email = data.get('email')
    
    if not token or not email:
        return jsonify({'error': 'Token and email are required'}), 400
    
    # Verify token via user service
    result = user_client.verify_email(email, token)
    
    if not result.get('success'):
        return jsonify({'error': result.get('message', 'Verification failed')}), 400
    
    # Get updated user data
    updated_user_data = result.get('user')
    if not updated_user_data:
        return jsonify({'error': 'Failed to get updated user data'}), 500
    
    # Convert user data to dict format for token generation
    user_dict = {
        'user_id': updated_user_data.get('userId'),
        'email': updated_user_data.get('email'),
        'first_name': updated_user_data.get('firstName'),
        'last_name': updated_user_data.get('lastName'),
        'type': updated_user_data.get('type'),
        'email_verified': updated_user_data.get('emailVerified', True),
        'active': updated_user_data.get('active', True),
        'profile_image_url': updated_user_data.get('profileImageUrl')
    }
    
    # Generate new JWT token with updated user info
    new_token = auth_service.generate_token(user_dict)
    
    return jsonify({
        'message': 'Email verified successfully',
        'token': new_token,
        'user': {
            'userId': updated_user_data.get('userId'),
            'email': updated_user_data.get('email'),
            'firstName': updated_user_data.get('firstName'),
            'lastName': updated_user_data.get('lastName'),
            'pendingEmail': updated_user_data.get('pendingEmail'),
            'type': updated_user_data.get('type'),
            'active': updated_user_data.get('active', True),
            'profileImageUrl': updated_user_data.get('profileImageUrl')
        }
    }), 200


@auth_bp.route('/resend-verification', methods=['POST'])
@handle_exceptions
def resend_verification():
    """Resend verification email (Token Reusability: returns same token if still valid)
    Can be used for initial verification or after email update
    """
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    # Get user
    user = user_client.get_user_by_email(email)
    if not user:
        user = user_client.get_user_by_pending_email(email)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Allow resending verification even if email was previously verified but is now unverified (after email update)
    # Only block if email is currently verified
    if user.get('email_verified') and not user.get('pending_email'):
        return jsonify({'error': 'Email is already verified'}), 400

    pending_email = user.get('pending_email')
    if pending_email and email != pending_email:
        return jsonify({'error': 'Pending email verification required'}), 400
    
    # Check if user has a valid verification token (Token Reusability)
    user_id = user.get('user_id')
    valid_token_data = user_client.get_valid_verification_token(user_id)
    
    if valid_token_data.get('token'):
        # Token is still valid, reuse it
        verification_token = valid_token_data.get('token')
    else:
        # Token doesn't exist or is expired, generate new one
        verification_token = auth_service.generate_verification_token()
        token_expires = auth_service.get_token_expiry()
        
        # Update user's verification token
        user_client.update_verification_token(
            user_id,
            verification_token,
            token_expires.isoformat()
        )
    
    # Send verification email with the token (either reused or new)
    target_email = pending_email or user.get('email')
    message_queue.send_verification_email(
        email=target_email,
        first_name=user.get('first_name'),
        token=verification_token
    )
    
    return jsonify({'message': 'Verification email sent'}), 200


@auth_bp.route('/refresh-token', methods=['POST'])
@handle_exceptions
def refresh_token():
    """Refresh JWT token"""
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'No token provided'}), 401
    
    old_token = auth_header.split(' ')[1]
    
    try:
        # Decode the old token (allow expired)
        payload = auth_service.decode_token(old_token, verify_exp=False)
        
        # Get fresh user data
        user = user_client.get_user_by_id(payload.get('userId'))
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if not user.get('active'):
            return jsonify({'error': 'Account has been banned'}), 403
        
        # Generate new token
        new_token = auth_service.generate_token(user)
        
        return jsonify({
            'message': 'Token refreshed',
            'token': new_token
        }), 200
        
    except Exception as e:
        return jsonify({'error': 'Invalid token'}), 401
