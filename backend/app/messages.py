"""Message routes for sending and retrieving encrypted messages."""

from flask import Blueprint, request, jsonify, session
from app import db
from app.models import Message, ConversationParticipant, File, Key, MessageReadStatus
from app.auth_utils import require_signature
from app.constants import (
    MAX_FILE_SIZE,
    ERROR_NOT_CONVERSATION_MEMBER, ERROR_DUPLICATE_NONCE, ERROR_DATABASE_ERROR,
    ERROR_FAILED_TO_SEND, ERROR_INVALID_BASE64, ERROR_MESSAGE_NOT_FOUND,
    ERROR_NOT_MESSAGE_OWNER, ERROR_FAILED_TO_DELETE, ERROR_INVALID_BEFORE_TIMESTAMP,
    ERROR_CONVERSATION_KEY_NOT_FOUND, ERROR_CONVERSATION_ID_REQUIRED,
    ERROR_MESSAGE_IDS_MUST_BE_LIST, ERROR_UNAUTHORIZED_ACCESS, ERROR_FAILED_TO_MARK_READ
)
from app.errors import (
    validation_error_response, forbidden_response,
    not_found_response, conflict_response, server_error_response
)
from sqlalchemy.exc import IntegrityError
import base64

messages_bp = Blueprint('messages', __name__, url_prefix='/api/messages')


@messages_bp.route('/send', methods=['POST'])
@require_signature
def send_message():
    """
    Send an encrypted message with optional attachment.
    
    Expected data:
    {
        "conversation_id": int,
        "encrypted_content": str (base64),
        "nonce": str (hex),
        "signature": str (hex),
        "attachment": {  # optional
            "filename": str,
            "encrypted_data": str (base64),
            "nonce": str (hex),
            "original_size": int,
            "mime_type": str
        }
    }
    """
    user_id = session['user_id']
    data = request.signed_data
    
    # Validate required fields
    if 'conversation_id' not in data:
        return validation_error_response('conversation_id is required')
    if 'encrypted_content' not in data:
        return validation_error_response('encrypted_content is required')
    if 'nonce' not in data:
        return validation_error_response('nonce is required')
    if 'signature' not in data:
        return validation_error_response('signature is required')
    
    conversation_id = data['conversation_id']
    
    # Verify user is participant in conversation
    participant = ConversationParticipant.query.filter_by(
        user_id=user_id,
        conversation_id=conversation_id
    ).first()
    
    if not participant:
        return forbidden_response(ERROR_NOT_CONVERSATION_MEMBER)
    
    # Create message
    message = Message(
        encrypted_content=data['encrypted_content'],
        nonce=data['nonce'],
        signature=data['signature'],
        user_id=user_id,
        conversation_id=conversation_id
    )
    
    try:
        db.session.add(message)
        db.session.flush()  # Get message ID before handling attachment
        
        # Handle attachment if present
        if 'attachment' in data and data['attachment']:
            attachment = data['attachment']
            
            # Validate attachment fields
            if 'encrypted_data' not in attachment:
                return validation_error_response('attachment.encrypted_data is required')
            if 'nonce' not in attachment:
                return validation_error_response('attachment.nonce is required')
            if 'original_size' not in attachment:
                return validation_error_response('attachment.original_size is required')
            
            # Decode base64 encrypted data
            try:
                encrypted_data = base64.b64decode(attachment['encrypted_data'])
            except Exception:
                return validation_error_response(ERROR_INVALID_BASE64)
            
            # Check file size (encrypted size)
            if len(encrypted_data) > MAX_FILE_SIZE:
                return validation_error_response(f'File too large. Max size is {MAX_FILE_SIZE / 1024 / 1024}MB')
            
            # Create file record
            file_record = File(
                filename=attachment.get('filename', 'attachment'),
                encrypted_data=encrypted_data,
                nonce=attachment['nonce'],
                file_size=len(encrypted_data),
                original_size=attachment['original_size'],
                mime_type=attachment.get('mime_type'),
                message_id=message.id
            )
            db.session.add(file_record)
        
        db.session.commit()
        
        db.session.refresh(message)
        
        # Emit WebSocket event to other participants
        from app.socket_events import emit_message_sent
        message_dict = message.to_dict()
        
        # Include attachments in WebSocket message
        attachments = message.files.all()
        if attachments:
            message_dict['attachments'] = [f.to_dict(include_data=True) for f in attachments]
        
        emit_message_sent(conversation_id, message_dict)
        
        return jsonify({
            'message': 'Message sent successfully',
            'message_id': message.id,
            'created_at': message.created_at.isoformat()
        }), 201
        
    except IntegrityError as e:
        db.session.rollback()
        if 'unique_conversation_nonce' in str(e):
            return conflict_response(ERROR_DUPLICATE_NONCE)
        return server_error_response(ERROR_DATABASE_ERROR)
    except Exception as e:
        db.session.rollback()
        return server_error_response(ERROR_FAILED_TO_SEND)


@messages_bp.route('/<int:conversation_id>', methods=['GET'])
@require_signature
def get_messages(conversation_id):
    """
    Get paginated messages for a conversation.
    
    Query params:
    - before: timestamp (ISO format) - Get messages before this time
    - limit: int (default 15) - Number of messages to return
    """
    user_id = session['user_id']
    
    # Verify user is participant
    participant = ConversationParticipant.query.filter_by(
        user_id=user_id,
        conversation_id=conversation_id
    ).first()
    
    if not participant:
        return forbidden_response(ERROR_NOT_CONVERSATION_MEMBER)
    
    # Get pagination params
    before = request.args.get('before')
    limit = min(int(request.args.get('limit', 15)), 50)  # Max 50 messages
    
    # Build query
    query = Message.query.filter_by(conversation_id=conversation_id)
    
    if before:
        # Parse timestamp and filter
        from datetime import datetime
        try:
            before_dt = datetime.fromisoformat(before.replace('Z', '+00:00'))
            query = query.filter(Message.created_at < before_dt)
        except ValueError:
            return validation_error_response(ERROR_INVALID_BEFORE_TIMESTAMP)
    
    # Order by newest first, then limit
    messages = query.order_by(Message.created_at.desc()).limit(limit).all()
    
    # Get attachments and read status for each message
    from app.models import MessageReadStatus
    result = []
    for msg in messages:
        msg_dict = msg.to_dict()
        
        # Add attachment info if present
        attachments = msg.files.all()
        if attachments:
            msg_dict['attachments'] = [f.to_dict(include_data=True) for f in attachments]
        
        # Check if current user has read this message
        read_status = MessageReadStatus.query.filter_by(
            message_id=msg.id,
            user_id=user_id
        ).first()
        msg_dict['read_by_me'] = read_status is not None
        
        # Check if recipient has read this message (for messages sent by current user)
        if msg.user_id == user_id:
            # Get the other participant
            participants = ConversationParticipant.query.filter_by(
                conversation_id=conversation_id
            ).all()
            other_participant_ids = [p.user_id for p in participants if p.user_id != user_id]
            
            # Check if any other participant has read it
            if other_participant_ids:
                read_by_recipient = MessageReadStatus.query.filter(
                    MessageReadStatus.message_id == msg.id,
                    MessageReadStatus.user_id.in_(other_participant_ids)
                ).first() is not None
                msg_dict['read_by_recipient'] = read_by_recipient
            else:
                msg_dict['read_by_recipient'] = False
        
        result.append(msg_dict)
    
    # Reverse to get chronological order (oldest first)
    result.reverse()
    
    return jsonify({
        'messages': result,
        'has_more': len(messages) == limit
    }), 200


@messages_bp.route('/conversation/<int:conversation_id>/key', methods=['GET'])
@require_signature
def get_conversation_key(conversation_id):
    """Get the encrypted conversation key for the current user."""
    user_id = session['user_id']
    
    # Verify user is participant
    participant = ConversationParticipant.query.filter_by(
        user_id=user_id,
        conversation_id=conversation_id
    ).first()
    
    if not participant:
        return forbidden_response(ERROR_NOT_CONVERSATION_MEMBER)
    
    # Get user's encrypted key for this conversation
    key = Key.query.filter_by(
        user_id=user_id,
        conversation_id=conversation_id
    ).first()
    
    if not key:
        return not_found_response(ERROR_CONVERSATION_KEY_NOT_FOUND)
    
    # Parse key_data JSON
    import json
    key_data = json.loads(key.key_data)
    
    return jsonify({
        'encrypted': key_data['encrypted'],
        'iv': key_data['iv'],
        'conversation_id': conversation_id
    }), 200


@messages_bp.route('/<int:message_id>', methods=['DELETE'])
@require_signature
def delete_message(message_id):
    """Delete a message from database. User can only delete their own messages."""
    user_id = session['user_id']
    
    # Get the message
    message = Message.query.get(message_id)
    
    if not message:
        return not_found_response(ERROR_MESSAGE_NOT_FOUND)
    
    # Verify user owns the message
    if message.user_id != user_id:
        return forbidden_response(ERROR_NOT_MESSAGE_OWNER)
    
    conversation_id = message.conversation_id
    
    try:
        # Actually delete the message from database
        db.session.delete(message)
        db.session.commit()
        
        # Emit WebSocket event to notify participants
        from app.socket_events import emit_message_deleted
        emit_message_deleted(conversation_id, message_id)
        
        return jsonify({'message': 'Message deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return server_error_response(ERROR_FAILED_TO_DELETE)


@messages_bp.route('/mark-read', methods=['POST'])
@require_signature
def mark_messages_as_read():
    """
    Mark multiple messages as read by the current user.
    
    Expected data:
    {
        "conversation_id": int,
        "message_ids": [int, int, ...]
    }
    """
    user_id = session['user_id']
    data = request.signed_data
    
    if 'conversation_id' not in data:
        return validation_error_response(ERROR_CONVERSATION_ID_REQUIRED)
    if 'message_ids' not in data or not isinstance(data['message_ids'], list):
        return validation_error_response(ERROR_MESSAGE_IDS_MUST_BE_LIST)
    
    conversation_id = data['conversation_id']
    message_ids = data['message_ids']
    
    # Verify user is participant
    participant = ConversationParticipant.query.filter_by(
        user_id=user_id,
        conversation_id=conversation_id
    ).first()
    
    if not participant:
        return forbidden_response(ERROR_UNAUTHORIZED_ACCESS)
    
    marked_count = 0
    
    try:
        for message_id in message_ids:
            # Check if message exists and belongs to conversation
            message = Message.query.filter_by(
                id=message_id,
                conversation_id=conversation_id
            ).first()
            
            if not message:
                continue
            
            # Don't mark own messages as read
            if message.user_id == user_id:
                continue
            
            # Check if already marked as read
            existing = MessageReadStatus.query.filter_by(
                message_id=message_id,
                user_id=user_id
            ).first()
            
            if not existing:
                read_status = MessageReadStatus(
                    message_id=message_id,
                    user_id=user_id
                )
                db.session.add(read_status)
                marked_count += 1
        
        db.session.commit()
        
        # Emit WebSocket event to notify message senders
        if marked_count > 0:
            from app.socket_events import emit_messages_read
            emit_messages_read(conversation_id, message_ids, user_id)
        
        return jsonify({
            'message': 'Messages marked as read',
            'marked_count': marked_count
        }), 200
    except Exception as e:
        db.session.rollback()
        return server_error_response(ERROR_FAILED_TO_MARK_READ)
