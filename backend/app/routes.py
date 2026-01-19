"""Main application routes."""

from flask import Blueprint, jsonify

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """API root endpoint - health check."""
    return jsonify({
        'status': 'online',
        'message': 'Secure Chat API',
        'version': '1.0.0',
        'endpoints': {
            'auth': '/api',
            'docs': '/api/docs'
        }
    }), 200


@main_bp.route('/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy'}), 200

