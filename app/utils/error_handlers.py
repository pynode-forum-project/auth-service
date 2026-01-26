from flask import jsonify
import logging

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Custom exception for validation errors"""
    def __init__(self, message, details=None):
        self.message = message
        self.details = details
        super().__init__(self.message)


class AuthenticationError(Exception):
    """Custom exception for authentication errors"""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class AuthorizationError(Exception):
    """Custom exception for authorization errors"""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class NotFoundError(Exception):
    """Custom exception for resource not found"""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class ServiceUnavailableError(Exception):
    """Custom exception for service unavailable"""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


def register_error_handlers(app):
    """Register global error handlers"""
    
    @app.errorhandler(ValidationError)
    def handle_validation_error(error):
        logger.warning(f'Validation error: {error.message}')
        response = {'error': 'Validation Error', 'message': error.message}
        if error.details:
            response['details'] = error.details
        return jsonify(response), 400
    
    @app.errorhandler(AuthenticationError)
    def handle_authentication_error(error):
        logger.warning(f'Authentication error: {error.message}')
        return jsonify({'error': 'Authentication Error', 'message': error.message}), 401
    
    @app.errorhandler(AuthorizationError)
    def handle_authorization_error(error):
        logger.warning(f'Authorization error: {error.message}')
        return jsonify({'error': 'Authorization Error', 'message': error.message}), 403
    
    @app.errorhandler(NotFoundError)
    def handle_not_found_error(error):
        logger.info(f'Not found: {error.message}')
        return jsonify({'error': 'Not Found', 'message': error.message}), 404
    
    @app.errorhandler(ServiceUnavailableError)
    def handle_service_unavailable_error(error):
        logger.error(f'Service unavailable: {error.message}')
        return jsonify({'error': 'Service Unavailable', 'message': error.message}), 503
    
    @app.errorhandler(400)
    def handle_bad_request(error):
        return jsonify({'error': 'Bad Request', 'message': str(error)}), 400
    
    @app.errorhandler(404)
    def handle_not_found(error):
        return jsonify({'error': 'Not Found', 'message': 'The requested resource was not found'}), 404
    
    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        return jsonify({'error': 'Method Not Allowed', 'message': 'This method is not allowed for this endpoint'}), 405
    
    @app.errorhandler(500)
    def handle_internal_error(error):
        logger.error(f'Internal server error: {str(error)}')
        return jsonify({'error': 'Internal Server Error', 'message': 'An unexpected error occurred'}), 500
