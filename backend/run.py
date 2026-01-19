#!/usr/bin/env python3
"""Main application entry point."""

import os
from app import create_app, db
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


@app.cli.command()
def seed_db():
    """Seed the database with sample data."""
    # Create sample users
    user1 = User(username='alice', email='alice@example.com', twofa_secret='SECRET1', password_hash='hash1')
    user2 = User(username='bob', email='bob@example.com', twofa_secret='SECRET2', password_hash='hash2')
    user3 = User(username='charlie', email='charlie@example.com', twofa_secret='SECRET3', password_hash='hash3')
    
    db.session.add_all([user1, user2, user3])
    db.session.commit()
    
    # Create sample conversations
    conv1 = Conversation(name='Project Discussion')
    conv2 = Conversation(name='Weekend Plans')
    
    db.session.add_all([conv1, conv2])
    db.session.commit()
    
    # Add participants to conversations
    # Conversation 1: Alice and Bob
    part1 = ConversationParticipant(user_id=user1.id, conversation_id=conv1.id)
    part2 = ConversationParticipant(user_id=user2.id, conversation_id=conv1.id)
    
    # Conversation 2: All three users
    part3 = ConversationParticipant(user_id=user1.id, conversation_id=conv2.id)
    part4 = ConversationParticipant(user_id=user2.id, conversation_id=conv2.id)
    part5 = ConversationParticipant(user_id=user3.id, conversation_id=conv2.id)
    
    db.session.add_all([part1, part2, part3, part4, part5])
    db.session.commit()
    
    # Create sample messages
    msg1 = Message(content='Hey Bob, how is the project going?', user_id=user1.id, conversation_id=conv1.id)
    msg2 = Message(content='Going well! Almost done with the backend.', user_id=user2.id, conversation_id=conv1.id)
    msg3 = Message(content='Anyone free this weekend?', user_id=user1.id, conversation_id=conv2.id)
    msg4 = Message(content='I am! What did you have in mind?', user_id=user3.id, conversation_id=conv2.id)
    
    db.session.add_all([msg1, msg2, msg3, msg4])
    db.session.commit()
    
    # Create sample keys for each user in each conversation
    key1 = Key(user_id=user1.id, conversation_id=conv1.id, key_data='encrypted_key_alice_conv1')
    key2 = Key(user_id=user2.id, conversation_id=conv1.id, key_data='encrypted_key_bob_conv1')
    key3 = Key(user_id=user1.id, conversation_id=conv2.id, key_data='encrypted_key_alice_conv2')
    key4 = Key(user_id=user2.id, conversation_id=conv2.id, key_data='encrypted_key_bob_conv2')
    key5 = Key(user_id=user3.id, conversation_id=conv2.id, key_data='encrypted_key_charlie_conv2')
    
    db.session.add_all([key1, key2, key3, key4, key5])
    db.session.commit()
    
    # Create sample encrypted files
    file1 = File(
        filename='project_document.pdf',
        encrypted_data=b'ENCRYPTED_PDF_DATA_HERE',
        file_size=1024,
        mime_type='application/pdf',
        message_id=msg1.id
    )
    file2 = File(
        filename='screenshot.png',
        encrypted_data=b'ENCRYPTED_IMAGE_DATA_HERE',
        file_size=2048,
        mime_type='image/png',
        message_id=msg2.id
    )
    
    db.session.add_all([file1, file2])
    db.session.commit()
    
    # Create sample read statuses
    # Bob has read Alice's message in conv1
    read1 = MessageReadStatus(message_id=msg1.id, user_id=user2.id)
    # Alice has read Bob's message in conv1
    read2 = MessageReadStatus(message_id=msg2.id, user_id=user1.id)
    # Bob and Charlie have read Alice's message in conv2
    read3 = MessageReadStatus(message_id=msg3.id, user_id=user2.id)
    read4 = MessageReadStatus(message_id=msg3.id, user_id=user3.id)
    # Alice has read Charlie's message in conv2
    read5 = MessageReadStatus(message_id=msg4.id, user_id=user1.id)
    
    db.session.add_all([read1, read2, read3, read4, read5])
    db.session.commit()
    
    print('Database seeded with sample data!')
    print('- 3 users (alice, bob, charlie)')
    print('- 2 conversations')
    print('- 4 messages')
    print('- 5 encryption keys')
    print('- 2 encrypted files')
    print('- 5 read statuses')


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
