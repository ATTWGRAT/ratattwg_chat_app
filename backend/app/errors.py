"""Centralized error response handlers."""

from flask import jsonify
from app.constants import (
    ERROR_UNAUTHORIZED,
    ERROR_INVALID_DATA
)


def error_response(message, status_code=400):
    """Create standardized error response."""
    return jsonify({'error': message}), status_code


def unauthorized_response(message=ERROR_UNAUTHORIZED):
    """Return 401 Unauthorized response."""
    return error_response(message, 401)


def forbidden_response(message="Forbidden"):
    """Return 403 Forbidden response."""
    return error_response(message, 403)


def not_found_response(message="Resource not found"):
    """Return 404 Not Found response."""
    return error_response(message, 404)


def conflict_response(message="Resource conflict"):
    """Return 409 Conflict response."""
    return error_response(message, 409)


def validation_error_response(message=ERROR_INVALID_DATA):
    """Return 400 Bad Request for validation errors."""
    return error_response(message, 400)


def server_error_response(message="Internal server error"):
    """Return 500 Internal Server Error response."""
    return error_response(message, 500)


def success_response(data=None, message=None, status_code=200):
    """Create standardized success response."""
    response = {}
    if data is not None:
        response.update(data) if isinstance(data, dict) else response.update({'data': data})
    if message:
        response['message'] = message
    return jsonify(response), status_code
