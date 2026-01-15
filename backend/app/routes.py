"""Main application routes."""

from flask import Blueprint, render_template, session
from app import db
from app.models import User

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Home page."""
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return render_template('index.html', user=user)
    return render_template('index.html', user=None)
