import eventlet
eventlet.monkey_patch()

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_socketio import SocketIO
from config import config
from app.session_manager import SessionManager

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
socketio = SocketIO()

# Thread-safe session manager for tracking active WebSocket connections
session_manager = SessionManager()


def create_app(config_name='default'):
    """Application factory pattern."""
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])
    
    # Set up logging
    from app.logging_config import setup_logging
    setup_logging(app)
    
    # Initialize extensions with app
    db.init_app(app)
    migrate.init_app(app, db)
    
    # Initialize SocketIO with CORS support
    socketio.init_app(app, 
                     cors_allowed_origins=app.config['CORS_ORIGINS'],
                     manage_session=False,  # Use Flask sessions
                     async_mode='eventlet',
                     logger=True,  # Enable logging for debugging
                     engineio_logger=True,  # Enable engine.io logging
                     ping_timeout=60,
                     ping_interval=25)
    
    # Enable CORS for React frontend
    CORS(app, 
         origins=app.config['CORS_ORIGINS'],
         supports_credentials=True,
         allow_headers=['Content-Type', 'Authorization', 'X-Signature-Data'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
    
    # Register blueprints
    from app.routes import main_bp
    from app.auth import auth_bp
    from app.friends import friends
    from app.messages import messages_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(friends)
    app.register_blueprint(messages_bp)
    
    # Create instance folder if it doesn't exist
    import os
    instance_path = os.path.join(app.root_path, '..', 'instance')
    os.makedirs(instance_path, exist_ok=True)
    
    # Initialize database tables
    with app.app_context():
        # Import models to register them with SQLAlchemy
        from app.models import User, Conversation, Message, ConversationParticipant, Key, File, MessageReadStatus, FriendRequest
        # Create all tables if they don't exist
        db.create_all()
        app.logger.info("Database tables initialized")
        
        # Import socket events (registers handlers)
        from . import socket_events
    
    return app
