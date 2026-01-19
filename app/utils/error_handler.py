# error_handler.py
# Global error handler for auth service

from flask import jsonify
from app.utils.exceptions import (
    AuthServiceError,
    InvalidCredentialsError,
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidTokenError,
    MissingTokenError,
    UserServiceError
)

def register_error_handlers(app):
    """Register global error handlers for the Flask app"""
    
    @app.errorhandler(AuthServiceError)
    def handle_auth_error(e):
        """Handle custom auth service errors"""
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(InvalidCredentialsError)
    def handle_invalid_credentials(e):
        """Handle invalid credentials error"""
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(UserNotFoundError)
    def handle_user_not_found(e):
        """Handle user not found error"""
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(UserAlreadyExistsError)
    def handle_user_exists(e):
        """Handle user already exists error"""
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(InvalidTokenError)
    def handle_invalid_token(e):
        """Handle invalid token error"""
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(MissingTokenError)
    def handle_missing_token(e):
        """Handle missing token error"""
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(UserServiceError)
    def handle_user_service_error(e):
        """Handle user service communication error"""
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(404)
    def handle_not_found(e):
        """Handle 404 errors"""
        return jsonify({
            'error': 'Endpoint not found',
            'status_code': 404
        }), 404
    
    @app.errorhandler(500)
    def handle_internal_error(e):
        """Handle internal server errors"""
        return jsonify({
            'error': 'Internal server error',
            'status_code': 500
        }), 500
