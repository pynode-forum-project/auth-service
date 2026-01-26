from flask import Flask
from flask_cors import CORS
from app.routes import auth_bp
from app.utils.error_handlers import register_error_handlers

def create_app():
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object('app.config.Config')
    
    # Enable CORS
    CORS(app, resources={r"/*": {"origins": "*"}})
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Health check endpoint
    @app.route('/health')
    def health():
        return {'status': 'healthy', 'service': 'auth-service'}
    
    return app
