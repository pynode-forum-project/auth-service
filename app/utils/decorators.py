from functools import wraps
from flask import jsonify
import logging

logger = logging.getLogger(__name__)


def handle_exceptions(f):
    """Decorator to handle exceptions in route handlers"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            logger.warning(f'Validation error in {f.__name__}: {str(e)}')
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except PermissionError as e:
            logger.warning(f'Permission denied in {f.__name__}: {str(e)}')
            return jsonify({'error': 'Access denied', 'message': str(e)}), 403
        except Exception as e:
            logger.error(f'Error in {f.__name__}: {str(e)}', exc_info=True)
            return jsonify({'error': 'Internal server error', 'message': str(e)}), 500
    return decorated_function


def log_request(f):
    """Decorator to log incoming requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from flask import request
        logger.info(f'{request.method} {request.path} - {request.remote_addr}')
        return f(*args, **kwargs)
    return decorated_function
