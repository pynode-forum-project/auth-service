import jwt
from datetime import datetime, timedelta
from flask import current_app, request, jsonify
from app.utils.exceptions import InvalidTokenError, MissingTokenError
from functools import wraps

def generate_token(user_id, user_type='normal_user', is_active=False):
    payload = {
        'user_id': user_id,
        'user_type': user_type,
        'is_active': is_active,
        'exp': datetime.utcnow() + current_app.config['JWT_ACCESS_TOKEN_EXPIRES'],
        'iat': datetime.utcnow()
    }
    
    token = jwt.encode(
        payload,
        current_app.config['JWT_SECRET_KEY'],
        algorithm=current_app.config['JWT_ALGORITHM']
    )
    
    return token if isinstance(token, str) else token.decode('utf-8')

def decode_token(token):
    try:
        payload = jwt.decode(
            token,
            current_app.config['JWT_SECRET_KEY'],
            algorithms=[current_app.config['JWT_ALGORITHM']]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise InvalidTokenError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise InvalidTokenError(f"Invalid token: {str(e)}")

def get_token_from_header():
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        raise MissingTokenError("Authorization header is missing")
    
    try:
        token_type, token = auth_header.split(' ', 1)
        if token_type.lower() != 'bearer':
            raise MissingTokenError("Authorization header must start with 'Bearer'")
        return token
    except ValueError:
        raise MissingTokenError("Invalid Authorization header format")

def verify_token(token=None):
    if token is None:
        token = get_token_from_header()
    
    return decode_token(token)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            payload = verify_token()
            request.current_user_id = payload['user_id']
            request.current_user_type = payload.get('user_type', 'normal_user')
            request.current_user_is_active = payload.get('is_active', False)
        except (InvalidTokenError, MissingTokenError) as e:
            return jsonify({'error': str(e)}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            payload = verify_token()
            user_type = payload.get('user_type', 'normal_user')
            
            if user_type not in ['admin', 'super_admin']:
                return jsonify({'error': 'Admin privileges required'}), 403
            
            request.current_user_id = payload['user_id']
            request.current_user_type = user_type
            request.current_user_is_active = payload.get('is_active', False)
        except (InvalidTokenError, MissingTokenError) as e:
            return jsonify({'error': str(e)}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function
