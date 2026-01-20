import jwt
from datetime import datetime, timedelta
from flask import current_app
from app.utils.exceptions import InvalidTokenError

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
