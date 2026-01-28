"""Friend request routes for managing chat invitations."""

from flask import Blueprint, request, jsonify, session
from app import db
from app.models import User, FriendRequest, Conversation, ConversationParticipant, Key, Message, File, MessageReadStatus
from app.auth_utils import require_signature
from app.socket_events import emit_friend_request_sent, emit_friend_request_accepted, emit_friend_request_rejected, emit_friend_removed
from app.constants import (
    ERROR_USER_NOT_FOUND, ERROR_SELF_FRIEND_REQUEST, ERROR_FRIEND_REQUEST_EXISTS,
    ERROR_ALREADY_FRIENDS, ERROR_INVALID_IV_FORMAT, ERROR_FRIEND_REQUEST_NOT_FOUND,
    ERROR_UNAUTHORIZED, ERROR_REQUEST_ALREADY_PROCESSED, ERROR_FRIENDSHIP_NOT_FOUND,
    ERROR_MISSING_FIELDS, ERROR_NOT_AUTHENTICATED
)
from app.errors import (
    validation_error_response, not_found_response,
    forbidden_response, conflict_response, unauthorized_response
)

friends = Blueprint('friends', __name__, url_prefix='/api/friends')


@friends.route('/search', methods=['POST'])
@require_signature
def search_users():
    """
    Get all users for client-side filtering.
    Returns username and public key for friend requests.
    """
    # Get current user to exclude from results
    current_user_id = session['user_id']
    
    # Return all users except the current user
    users = User.query.filter(User.id != current_user_id).all()
    
    return jsonify({
        'users': [{
            'id': user.id,
            'username': user.username,
            'public_key': user.public_key
        } for user in users]
    }), 200


@friends.route('/request/send', methods=['POST'])
@require_signature
def send_friend_request():
    """
    Send a friend request to another user.
    
    Expected data:
    {
        "receiver_username": "username",
        "conversation_key_encrypted_for_receiver": "base64_encrypted_key",
        "conversation_key_encrypted_for_sender": "base64_encrypted_key",
        "sender_iv": "hex_iv",
        "signature_for_receiver": "hex_signature"
    }
    """
    data = request.signed_data
    sender_id = session['user_id']
    
    # Validate required fields
    required_fields = [
        'receiver_username',
        'conversation_key_encrypted_for_receiver',
        'conversation_key_encrypted_for_sender',
        'sender_iv',
        'signature_for_receiver'
    ]
    
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return validation_error_response(f'{ERROR_MISSING_FIELDS}: {", ".join(missing_fields)}')
    
    # Get receiver user
    receiver = User.query.filter_by(username=data['receiver_username']).first()
    if not receiver:
        return not_found_response(ERROR_USER_NOT_FOUND)
    
    if receiver.id == sender_id:
        return validation_error_response(ERROR_SELF_FRIEND_REQUEST)
    
    # Check if there's already a pending request between these users
    existing_request = FriendRequest.query.filter(
        db.or_(
            db.and_(
                FriendRequest.sender_id == sender_id,
                FriendRequest.receiver_id == receiver.id,
                FriendRequest.status == 'pending'
            ),
            db.and_(
                FriendRequest.sender_id == receiver.id,
                FriendRequest.receiver_id == sender_id,
                FriendRequest.status == 'pending'
            )
        )
    ).first()
    
    if existing_request:
        return conflict_response(ERROR_FRIEND_REQUEST_EXISTS)
    
    # Check if users are already friends (have an accepted request)
    existing_friendship = FriendRequest.query.filter(
        db.or_(
            db.and_(
                FriendRequest.sender_id == sender_id,
                FriendRequest.receiver_id == receiver.id,
                FriendRequest.status == 'accepted'
            ),
            db.and_(
                FriendRequest.sender_id == receiver.id,
                FriendRequest.receiver_id == sender_id,
                FriendRequest.status == 'accepted'
            )
        )
    ).first()
    
    if existing_friendship:
        return conflict_response(ERROR_ALREADY_FRIENDS)
    
    # Validate IV format (24 hex characters = 12 bytes for AES-GCM)
    if len(data['sender_iv']) != 24:
        return validation_error_response(ERROR_INVALID_IV_FORMAT)
    
    try:
        bytes.fromhex(data['sender_iv'])
    except ValueError:
        return validation_error_response(ERROR_INVALID_IV_FORMAT)
    
    # Create friend request
    friend_request = FriendRequest(
        sender_id=sender_id,
        receiver_id=receiver.id,
        conversation_key_encrypted_for_receiver=data['conversation_key_encrypted_for_receiver'],
        conversation_key_encrypted_for_sender=data['conversation_key_encrypted_for_sender'],
        sender_iv=data['sender_iv'],
        signature_for_receiver=data['signature_for_receiver'],
        status='pending'
    )
    
    db.session.add(friend_request)
    db.session.commit()
    
    # Emit WebSocket event to receiver
    emit_friend_request_sent(
        receiver_id=receiver.id,
        request_data={
            "id": friend_request.id,
            "sender": {
                "id": sender_id,
                "username": User.query.get(sender_id).username,
                "public_key": User.query.get(sender_id).public_key
            },
            "conversation_key_encrypted_for_receiver": friend_request.conversation_key_encrypted_for_receiver,
            "signature_for_receiver": friend_request.signature_for_receiver,
            "created_at": friend_request.created_at.isoformat(),
            "status": friend_request.status
        }
    )
    
    return jsonify({
        'message': 'Friend request sent successfully',
        'request_id': friend_request.id
    }), 201


@friends.route('/pending', methods=['GET'])
@require_signature
def get_pending_requests():
    """
    Get all pending friend requests for the current user.
    Returns requests where the current user is the receiver.
    """
    user_id = session.get('user_id')
    
    if not user_id:
        return unauthorized_response(ERROR_NOT_AUTHENTICATED)
    
    pending_requests = FriendRequest.query.filter_by(
        receiver_id=user_id,
        status='pending'
    ).all()
    
    return jsonify([{
        "id": req.id,
        "sender": {
            "id": req.sender.id,
            "username": req.sender.username,
            "public_key": req.sender.public_key
        },
        "conversation_key_encrypted_for_receiver": req.conversation_key_encrypted_for_receiver,
        "signature_for_receiver": req.signature_for_receiver,
        "created_at": req.created_at.isoformat(),
        "status": req.status
    } for req in pending_requests]), 200


@friends.route('/sent', methods=['GET'])
@require_signature
def get_sent_requests():
    """
    Get all pending friend requests sent by the current user.
    Returns requests where the current user is the sender.
    """
    user_id = session.get('user_id')
    
    if not user_id:
        return unauthorized_response(ERROR_NOT_AUTHENTICATED)
    
    sent_requests = FriendRequest.query.filter_by(
        sender_id=user_id,
        status='pending'
    ).all()
    
    return jsonify([{
        "id": req.id,
        "receiver": {
            "id": req.receiver.id,
            "username": req.receiver.username
        },
        "created_at": req.created_at.isoformat(),
        "status": req.status
    } for req in sent_requests]), 200


# Removed duplicate get_pending_requests_old() function
# Use GET /api/friends/pending instead (line 161)


@friends.route('/request/accept', methods=['POST'])
@require_signature
def accept_friend_request():
    """
    Accept a friend request.
    
    Expected data:
    {
        "request_id": 123,
        "conversation_key_encrypted_for_receiver": "base64_encrypted_key",
        "receiver_iv": "hex_iv"
    }
    """
    data = request.signed_data
    user_id = session['user_id']
    
    # Validate required fields
    if not data.get('request_id'):
        return validation_error_response('request_id is required')
    
    if not data.get('conversation_key_encrypted_for_receiver'):
        return validation_error_response('conversation_key_encrypted_for_receiver is required')
    
    if not data.get('receiver_iv'):
        return validation_error_response('receiver_iv is required')
    
    # Validate IV format (24 hex characters = 12 bytes for AES-GCM)
    if len(data['receiver_iv']) != 24:
        return validation_error_response(ERROR_INVALID_IV_FORMAT)
    
    try:
        bytes.fromhex(data['receiver_iv'])
    except ValueError:
        return validation_error_response(ERROR_INVALID_IV_FORMAT)
    
    # Get the friend request
    friend_request = FriendRequest.query.get(data['request_id'])
    
    if not friend_request:
        return not_found_response(ERROR_FRIEND_REQUEST_NOT_FOUND)
    
    if friend_request.receiver_id != user_id:
        return forbidden_response(ERROR_UNAUTHORIZED)
    
    if friend_request.status != 'pending':
        return validation_error_response(f'{ERROR_REQUEST_ALREADY_PROCESSED}: {friend_request.status}')
    
    # Create conversation
    conversation = Conversation(name=None)  # Private 1-on-1 conversation
    db.session.add(conversation)
    db.session.flush()  # Get conversation ID
    
    # Add both users as participants
    participant_sender = ConversationParticipant(
        user_id=friend_request.sender_id,
        conversation_id=conversation.id
    )
    participant_receiver = ConversationParticipant(
        user_id=friend_request.receiver_id,
        conversation_id=conversation.id
    )
    
    db.session.add(participant_sender)
    db.session.add(participant_receiver)
    
    # Create keys for both users
    # Store key_data as JSON with both encrypted key and IV
    import json
    sender_key_data = json.dumps({
        'encrypted': friend_request.conversation_key_encrypted_for_sender,
        'iv': friend_request.sender_iv
    })
    receiver_key_data = json.dumps({
        'encrypted': data['conversation_key_encrypted_for_receiver'],
        'iv': data['receiver_iv']
    })
    
    key_sender = Key(
        user_id=friend_request.sender_id,
        conversation_id=conversation.id,
        key_data=sender_key_data
    )
    
    key_receiver = Key(
        user_id=friend_request.receiver_id,
        conversation_id=conversation.id,
        key_data=receiver_key_data
    )
    
    db.session.add(key_sender)
    db.session.add(key_receiver)
    
    # Update friend request
    friend_request.status = 'accepted'
    friend_request.receiver_iv = data['receiver_iv']
    friend_request.conversation_id = conversation.id
    
    db.session.commit()
    
    # Emit WebSocket event to sender that request was accepted
    emit_friend_request_accepted(
        sender_id=friend_request.sender_id,
        receiver_id=friend_request.receiver_id,
        conversation_id=conversation.id
    )
    
    return jsonify({
        'message': 'Friend request accepted',
        'conversation_id': conversation.id
    }), 200


@friends.route('/request/reject', methods=['POST'])
@require_signature
def reject_friend_request():
    """
    Reject a friend request by deleting it.
    
    Expected data:
    {
        "request_id": 123
    }
    """
    data = request.signed_data
    user_id = session['user_id']
    
    if not data.get('request_id'):
        return validation_error_response('request_id is required')
    
    # Get the friend request
    friend_request = FriendRequest.query.get(data['request_id'])
    
    if not friend_request:
        return not_found_response(ERROR_FRIEND_REQUEST_NOT_FOUND)
    
    if friend_request.receiver_id != user_id:
        return forbidden_response(ERROR_UNAUTHORIZED)
    
    if friend_request.status != 'pending':
        return validation_error_response(f'{ERROR_REQUEST_ALREADY_PROCESSED}: {friend_request.status}')
    
    # Store sender_id before deletion
    sender_id = friend_request.sender_id
    request_id = friend_request.id
    
    # Delete the friend request
    db.session.delete(friend_request)
    db.session.commit()
    
    # Emit WebSocket event to sender that request was rejected
    emit_friend_request_rejected(
        sender_id=sender_id,
        receiver_id=user_id,
        request_id=request_id
    )
    
    return jsonify({'message': 'Friend request rejected'}), 200


@friends.route('/list', methods=['POST'])
@require_signature
def get_friends():
    """Get list of all friends (accepted friend requests) for the current user."""
    user_id = session['user_id']
    
    # Get all accepted friend requests where user is sender or receiver
    accepted_requests = FriendRequest.query.filter(
        db.or_(
            FriendRequest.sender_id == user_id,
            FriendRequest.receiver_id == user_id
        ),
        FriendRequest.status == 'accepted'
    ).all()
    
    friends_data = []
    for req in accepted_requests:
        # Get the other user (the friend)
        friend_id = req.receiver_id if req.sender_id == user_id else req.sender_id
        friend = User.query.get(friend_id)
        
        friends_data.append({
            'id': friend.id,
            'username': friend.username,
            'conversation_id': req.conversation_id,
            'friends_since': req.updated_at.isoformat()
        })
    
    return jsonify({'friends': friends_data}), 200


@friends.route('/remove/<int:friend_id>', methods=['DELETE'])
@require_signature
def remove_friend(friend_id):
    """
    Remove a friend by deleting the accepted friend request and associated conversation.
    
    Args:
        friend_id: ID of the friend to remove
    """
    user_id = session['user_id']
    
    # Find the accepted friend request between these two users
    friend_request = FriendRequest.query.filter(
        db.or_(
            db.and_(
                FriendRequest.sender_id == user_id,
                FriendRequest.receiver_id == friend_id,
                FriendRequest.status == 'accepted'
            ),
            db.and_(
                FriendRequest.sender_id == friend_id,
                FriendRequest.receiver_id == user_id,
                FriendRequest.status == 'accepted'
            )
        )
    ).first()
    
    if not friend_request:
        return not_found_response(ERROR_FRIENDSHIP_NOT_FOUND)
    
    conversation_id = friend_request.conversation_id
    
    # Get all message IDs for this conversation
    message_ids = [msg.id for msg in Message.query.filter_by(conversation_id=conversation_id).all()]
    
    # Delete child records of messages first
    if message_ids:
        # Delete message read statuses
        MessageReadStatus.query.filter(MessageReadStatus.message_id.in_(message_ids)).delete(synchronize_session=False)
        # Delete file attachments
        File.query.filter(File.message_id.in_(message_ids)).delete(synchronize_session=False)
    
    # Delete all messages in the conversation
    Message.query.filter_by(conversation_id=conversation_id).delete()
    
    # Delete conversation participants
    ConversationParticipant.query.filter_by(conversation_id=conversation_id).delete()
    
    # Delete encryption keys
    Key.query.filter_by(conversation_id=conversation_id).delete()
    
    # Delete the conversation itself
    Conversation.query.filter_by(id=conversation_id).delete()
    
    # Delete the friend request
    db.session.delete(friend_request)
    db.session.commit()
    
    # Emit WebSocket event to both users
    emit_friend_removed(
        user_id=user_id,
        friend_id=friend_id,
        conversation_id=conversation_id
    )
    
    return jsonify({'message': 'Friend removed successfully'}), 200
