import re


def validate_email(email: str) -> bool:
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_password(password: str) -> list:
    """
    Validate password strength
    Returns list of errors or empty list if valid
    """
    errors = []
    
    if len(password) < 8:
        errors.append('Password must be at least 8 characters long')
    
    if not re.search(r'[A-Z]', password):
        errors.append('Password must contain at least one uppercase letter')
    
    if not re.search(r'[a-z]', password):
        errors.append('Password must contain at least one lowercase letter')
    
    if not re.search(r'\d', password):
        errors.append('Password must contain at least one digit')
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append('Password must contain at least one special character')
    
    return errors


def validate_login(data: dict) -> dict:
    """
    Validate login request data
    Returns dict of field errors or empty dict if valid
    """
    errors = {}
    
    if not data:
        return {'general': 'Request body is required'}
    
    email = data.get('email')
    password = data.get('password')
    
    if not email:
        errors['email'] = 'Email is required'
    elif not validate_email(email):
        errors['email'] = 'Invalid email format'
    
    if not password:
        errors['password'] = 'Password is required'
    
    return errors


def validate_register(data: dict) -> dict:
    """
    Validate registration request data
    Returns dict of field errors or empty dict if valid
    """
    errors = {}
    
    if not data:
        return {'general': 'Request body is required'}
    
    # First name validation
    first_name = data.get('firstName')
    if not first_name:
        errors['firstName'] = 'First name is required'
    elif len(first_name) < 2:
        errors['firstName'] = 'First name must be at least 2 characters'
    elif len(first_name) > 50:
        errors['firstName'] = 'First name must not exceed 50 characters'
    
    # Last name validation
    last_name = data.get('lastName')
    if not last_name:
        errors['lastName'] = 'Last name is required'
    elif len(last_name) < 2:
        errors['lastName'] = 'Last name must be at least 2 characters'
    elif len(last_name) > 50:
        errors['lastName'] = 'Last name must not exceed 50 characters'
    
    # Email validation
    email = data.get('email')
    if not email:
        errors['email'] = 'Email is required'
    elif not validate_email(email):
        errors['email'] = 'Invalid email format'
    
    # Password validation
    password = data.get('password')
    if not password:
        errors['password'] = 'Password is required'
    else:
        password_errors = validate_password(password)
        if password_errors:
            errors['password'] = password_errors
    
    return errors
