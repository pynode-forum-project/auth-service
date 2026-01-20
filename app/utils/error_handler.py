# error_handler.py
# Global error handler for auth service

from flask import jsonify, current_app
from app.utils.exceptions import (
    AuthServiceError,
    InvalidCredentialsError,
    UserNotFoundError,
    UserAlreadyExistsError,
    InvalidTokenError,
    MissingTokenError,
    UserServiceError,
    ValidationError
)

def register_error_handlers(app):
    @app.errorhandler(AuthServiceError)
    def handle_auth_error(e):
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(InvalidCredentialsError)
    def handle_invalid_credentials(e):
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(UserNotFoundError)
    def handle_user_not_found(e):
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(UserAlreadyExistsError)
    def handle_user_exists(e):
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(InvalidTokenError)
    def handle_invalid_token(e):
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(MissingTokenError)
    def handle_missing_token(e):
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(UserServiceError)
    def handle_user_service_error(e):
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(ValidationError)
    def handle_validation_error(e):
        return jsonify({
            'error': e.message,
            'status_code': e.status_code
        }), e.status_code
    
    @app.errorhandler(404)
    def handle_not_found(e):
        return jsonify({
            'error': 'Endpoint not found',
            'status_code': 404
        }), 404
    
    @app.errorhandler(500)
    def handle_internal_error(e):
        current_app.logger.error(f"Internal server error: {str(e)}", exc_info=True)
        return jsonify({
            'error': 'Internal server error',
            'status_code': 500
        }), 500
