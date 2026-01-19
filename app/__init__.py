# __init__.py
# Flask application factory

from flask import Flask
from config import Config
from app.utils.error_handler import register_error_handlers

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register blueprints
    from app.routes.auth_routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    return app
