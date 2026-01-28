"""WebSocket events for real-time friend request notifications."""

from flask import session, request
from flask_socketio import join_room
from app import socketio, session_manager
from app.constants import (
    WS_EVENT_FRIEND_REQUEST, WS_EVENT_FRIEND_ACCEPTED, WS_EVENT_FRIEND_REJECTED,
    WS_EVENT_MESSAGE_RECEIVED, WS_EVENT_MESSAGE_DELETED, WS_EVENT_MESSAGES_READ,
    WS_EVENT_FORCE_LOGOUT, WS_EVENT_USER_REGISTERED
)


@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    from flask import current_app
    user_id = session.get('user_id')
    
    if user_id:
        # Add session to thread-safe session manager
        session_id = request.sid
        total_sessions = session_manager.add_session(user_id, session_id)
        
        # Join a room specific to this user for targeted notifications
        join_room(f'user_{user_id}')
        
        current_app.logger.info(f'[WebSocket] User {user_id} connected (session: {session_id}, total: {total_sessions})')
    else:
        current_app.logger.warning(f'[WebSocket] Anonymous connection (sid: {request.sid})')


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    user_id = session.get('user_id')
    session_id = request.sid
    
    if user_id:
        # Remove session from thread-safe session manager
        session_manager.remove_session(user_id, session_id)


def emit_user_registered(user_data):
    """
    Notify all connected users that a new user has registered.
    
    Args:
        user_data: User data to broadcast (id, username, public_key)
    """
    socketio.emit(
        WS_EVENT_USER_REGISTERED,
        user_data,
        namespace='/'
    )


def emit_friend_request_sent(receiver_id, request_data):
    """
    Notify receiver that they have a new friend request.
    
    Args:
        receiver_id: ID of the user who received the request
        request_data: Friend request data to send to receiver
    """
    from flask import current_app
    current_app.logger.debug(f'emitting event "{WS_EVENT_FRIEND_REQUEST}" to user_{receiver_id} [/]')
    socketio.emit(
        WS_EVENT_FRIEND_REQUEST,
        request_data,
        room=f'user_{receiver_id}',
        namespace='/'
    )


def emit_friend_request_accepted(sender_id, receiver_id, conversation_id):
    """
    Notify sender that their friend request was accepted.
    
    Args:
        sender_id: ID of the user who originally sent the request
        receiver_id: ID of the user who accepted the request
        conversation_id: ID of the newly created conversation
    """
    from flask import current_app
    current_app.logger.debug(f'emitting event "{WS_EVENT_FRIEND_ACCEPTED}" to user_{sender_id} [/]')
    socketio.emit(
        WS_EVENT_FRIEND_ACCEPTED,
        {
            'friend_id': receiver_id,
            'conversation_id': conversation_id
        },
        room=f'user_{sender_id}',
        namespace='/'
    )


def emit_friend_request_rejected(sender_id, receiver_id, request_id):
    """
    Notify sender that their friend request was rejected.
    
    Args:
        sender_id: ID of the user who originally sent the request
        receiver_id: ID of the user who rejected the request
        request_id: ID of the rejected friend request
    """
    from flask import current_app
    current_app.logger.debug(f'emitting event "{WS_EVENT_FRIEND_REJECTED}" to user_{sender_id} [/]')
    socketio.emit(
        WS_EVENT_FRIEND_REJECTED,
        {
            'receiver_id': receiver_id,
            'request_id': request_id
        },
        room=f'user_{sender_id}',
        namespace='/'
    )


def emit_force_logout(old_session_ids):
    """
    Force logout previous sessions when user logs in from new location.
    
    Args:
        old_session_ids: Set of socket session IDs to force logout
    """
    from flask import current_app
    for session_id in old_session_ids:
        current_app.logger.debug(f'emitting event "{WS_EVENT_FORCE_LOGOUT}" to session {session_id} [/]')
        socketio.emit(
            WS_EVENT_FORCE_LOGOUT,
            {'message': 'You have been logged in from another location'},
            to=session_id,
            namespace='/'
        )


def emit_friend_removed(user_id, friend_id, conversation_id):
    """
    Notify both users that their friendship has been removed.
    
    Args:
        user_id: ID of the user who removed the friend
        friend_id: ID of the friend who was removed
        conversation_id: ID of the conversation that was deleted
    """
    from flask import current_app
    current_app.logger.debug(f'emitting event "friend_removed" to user_{user_id} [/]')
    socketio.emit(
        'friend_removed',
        {
            'removed_friend_id': friend_id,
            'conversation_id': conversation_id
        },
        room=f'user_{user_id}',
        namespace='/'
    )
    
    current_app.logger.debug(f'emitting event "friend_removed" to user_{friend_id} [/]')
    socketio.emit(
        'friend_removed',
        {
            'removed_friend_id': user_id,
            'conversation_id': conversation_id
        },
        room=f'user_{friend_id}',
        namespace='/'
    )


def emit_message_sent(conversation_id, message_data):
    """
    Notify all participants in a conversation about a new message.
    
    Args:
        conversation_id: ID of the conversation
        message_data: Dictionary containing message details
    """
    from app.models import ConversationParticipant
    
    participants = ConversationParticipant.query.filter_by(
        conversation_id=conversation_id
    ).all()
    
    for participant in participants:
        room_name = f'user_{participant.user_id}'
        socketio.emit(
            WS_EVENT_MESSAGE_RECEIVED,
            {
                'conversation_id': conversation_id,
                'message': message_data
            },
            room=room_name,
            namespace='/'
        )


def emit_message_deleted(conversation_id, message_id):
    """
    Notify all participants in a conversation that a message was deleted.
    
    Args:
        conversation_id: ID of the conversation
        message_id: ID of the deleted message
    """
    from app.models import ConversationParticipant
    
    participants = ConversationParticipant.query.filter_by(
        conversation_id=conversation_id
    ).all()
    
    for participant in participants:
        socketio.emit(
            WS_EVENT_MESSAGE_DELETED,
            {
                'conversation_id': conversation_id,
                'message_id': message_id
            },
            room=f'user_{participant.user_id}',
            namespace='/'
        )


def emit_messages_read(conversation_id, message_ids, reader_id):
    """
    Notify message senders that their messages have been read.
    
    Args:
        conversation_id: ID of the conversation
        message_ids: List of message IDs that were read
        reader_id: ID of the user who read the messages
    """
    from app.models import ConversationParticipant
    
    participants = ConversationParticipant.query.filter_by(
        conversation_id=conversation_id
    ).all()
    
    for participant in participants:
        socketio.emit(
            WS_EVENT_MESSAGES_READ,
            {
                'conversation_id': conversation_id,
                'message_ids': message_ids,
                'reader_id': reader_id
            },
            room=f'user_{participant.user_id}',
            namespace='/'
        )
