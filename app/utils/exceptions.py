# exceptions.py
# Custom exceptions for auth service

class AuthServiceError(Exception):
    def __init__(self, message, status_code=400):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class InvalidCredentialsError(AuthServiceError):
    def __init__(self, message="Invalid email or password"):
        super().__init__(message, status_code=401)

class UserNotFoundError(AuthServiceError):
    def __init__(self, message="User not found"):
        super().__init__(message, status_code=404)

class UserAlreadyExistsError(AuthServiceError):
    def __init__(self, message="User with this email already exists"):
        super().__init__(message, status_code=409)

class InvalidTokenError(AuthServiceError):
    def __init__(self, message="Invalid or expired token"):
        super().__init__(message, status_code=401)

class MissingTokenError(AuthServiceError):
    def __init__(self, message="Authentication token is required"):
        super().__init__(message, status_code=401)

class UserServiceError(AuthServiceError):
    def __init__(self, message="User service communication error"):
        super().__init__(message, status_code=503)

class ValidationError(AuthServiceError):
    def __init__(self, message="Invalid request data"):
        super().__init__(message, status_code=400)
