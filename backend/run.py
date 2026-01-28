#!/usr/bin/env python3
"""Main application entry point."""

import eventlet
eventlet.monkey_patch()

import os
from app import create_app, db, socketio
from app.models import User, Conversation, Message, ConversationParticipant, Key, File, MessageReadStatus, FriendRequest

# Create the Flask application
app = create_app(os.getenv('FLASK_ENV', 'development'))


@app.shell_context_processor
def make_shell_context():
    """Register shell context objects."""
    return {
        'db': db,
        'User': User,
        'Conversation': Conversation,
        'Message': Message,
        'ConversationParticipant': ConversationParticipant,
        'Key': Key,
        'File': File,
        'MessageReadStatus': MessageReadStatus,
        'FriendRequest': FriendRequest
    }


@app.cli.command()
def init_db():
    """Initialize the database."""
    db.create_all()
    print('Database initialized!')

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)
