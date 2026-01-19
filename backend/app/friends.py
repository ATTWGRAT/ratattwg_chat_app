"""Friend request routes for managing chat invitations."""

from flask import Blueprint, request, jsonify, session
from app import db
from app.models import User, FriendRequest, Conversation, ConversationParticipant, Key
from app.auth_utils import require_signature, verify_signature
import time

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
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
    
    # Get receiver user
    receiver = User.query.filter_by(username=data['receiver_username']).first()
    if not receiver:
        return jsonify({'error': 'User not found'}), 404
    
    if receiver.id == sender_id:
        return jsonify({'error': 'Cannot send friend request to yourself'}), 400
    
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
        return jsonify({'error': 'Friend request already exists between these users'}), 400
    
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
        return jsonify({'error': 'Users are already friends'}), 400
    
    # Validate IV format (24 hex characters = 12 bytes for AES-GCM)
    if len(data['sender_iv']) != 24:
        return jsonify({'error': 'Invalid IV format: must be 24 hex characters (12 bytes)'}), 400
    
    try:
        bytes.fromhex(data['sender_iv'])
    except ValueError:
        return jsonify({'error': 'Invalid IV format'}), 400
    
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
        return jsonify({"error": "Not authenticated"}), 401
    
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
        return jsonify({"error": "Not authenticated"}), 401
    
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


@friends.route('/request/pending', methods=['POST'])
@require_signature
def get_pending_requests_old():
    """Get all pending friend requests for the current user."""
    user_id = session['user_id']
    
    # Get requests where current user is the receiver
    pending_requests = FriendRequest.query.filter_by(
        receiver_id=user_id,
        status='pending'
    ).all()
    
    # Get sender information for each request
    requests_data = []
    for req in pending_requests:
        sender = User.query.get(req.sender_id)
        requests_data.append({
            'id': req.id,
            'sender': {
                'id': sender.id,
                'username': sender.username,
                'public_key': sender.public_key
            },
            'conversation_key_encrypted_for_receiver': req.conversation_key_encrypted_for_receiver,
            'signature_for_receiver': req.signature_for_receiver,
            'created_at': req.created_at.isoformat()
        })
    
    return jsonify({'requests': requests_data}), 200


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
        return jsonify({'error': 'request_id is required'}), 400
    
    if not data.get('conversation_key_encrypted_for_receiver'):
        return jsonify({'error': 'conversation_key_encrypted_for_receiver is required'}), 400
    
    if not data.get('receiver_iv'):
        return jsonify({'error': 'receiver_iv is required'}), 400
    
    # Validate IV format (24 hex characters = 12 bytes for AES-GCM)
    if len(data['receiver_iv']) != 24:
        return jsonify({'error': 'Invalid IV format: must be 24 hex characters (12 bytes)'}), 400
    
    try:
        bytes.fromhex(data['receiver_iv'])
    except ValueError:
        return jsonify({'error': 'Invalid IV format'}), 400
    
    # Get the friend request
    friend_request = FriendRequest.query.get(data['request_id'])
    
    if not friend_request:
        return jsonify({'error': 'Friend request not found'}), 404
    
    if friend_request.receiver_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if friend_request.status != 'pending':
        return jsonify({'error': f'Request is already {friend_request.status}'}), 400
    
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
    key_sender = Key(
        user_id=friend_request.sender_id,
        conversation_id=conversation.id,
        key_data=friend_request.conversation_key_encrypted_for_sender
    )
    
    key_receiver = Key(
        user_id=friend_request.receiver_id,
        conversation_id=conversation.id,
        key_data=data['conversation_key_encrypted_for_receiver']
    )
    
    db.session.add(key_sender)
    db.session.add(key_receiver)
    
    # Update friend request
    friend_request.status = 'accepted'
    friend_request.receiver_iv = data['receiver_iv']
    friend_request.conversation_id = conversation.id
    
    db.session.commit()
    
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
        return jsonify({'error': 'request_id is required'}), 400
    
    # Get the friend request
    friend_request = FriendRequest.query.get(data['request_id'])
    
    if not friend_request:
        return jsonify({'error': 'Friend request not found'}), 404
    
    if friend_request.receiver_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if friend_request.status != 'pending':
        return jsonify({'error': f'Request is already {friend_request.status}'}), 400
    
    # Delete the friend request
    db.session.delete(friend_request)
    db.session.commit()
    
    # Notify sender that request was rejected
    # In a real app, this would be done via WebSocket or notification system
    
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
