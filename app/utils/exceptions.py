# exceptions.py
# Custom exceptions for auth service

class AuthServiceError(Exception):
    """Base exception for auth service errors"""
    def __init__(self, message, status_code=400):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class InvalidCredentialsError(AuthServiceError):
    """Raised when email/password combination is invalid"""
    def __init__(self, message="Invalid email or password"):
        super().__init__(message, status_code=401)

class UserNotFoundError(AuthServiceError):
    """Raised when user is not found"""
    def __init__(self, message="User not found"):
        super().__init__(message, status_code=404)

class UserAlreadyExistsError(AuthServiceError):
    """Raised when trying to register a user that already exists"""
    def __init__(self, message="User with this email already exists"):
        super().__init__(message, status_code=409)

class InvalidTokenError(AuthServiceError):
    """Raised when JWT token is invalid or expired"""
    def __init__(self, message="Invalid or expired token"):
        super().__init__(message, status_code=401)

class MissingTokenError(AuthServiceError):
    """Raised when JWT token is missing from request"""
    def __init__(self, message="Authentication token is required"):
        super().__init__(message, status_code=401)

class UserServiceError(AuthServiceError):
    """Raised when user service communication fails"""
    def __init__(self, message="User service communication error"):
        super().__init__(message, status_code=503)
