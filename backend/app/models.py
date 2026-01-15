from app import db
from datetime import datetime


class User(db.Model):
    """User model."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    twofa_secret = db.Column(db.String(32), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    encrypted_private_key = db.Column(db.Text, nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    encryption_iv = db.Column(db.String(32), nullable=False)
    
    # Relationships
    keys = db.relationship('Key', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    messages = db.relationship('Message', backref='author', lazy='dynamic', cascade='all, delete-orphan')
    participations = db.relationship('ConversationParticipant', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    read_statuses = db.relationship('MessageReadStatus', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def to_dict(self):
        """Convert model to dictionary."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'created_at': self.created_at.isoformat(),
            'twofa_secret': self.twofa_secret,
            'password_hash': self.password_hash
        }


class Conversation(db.Model):
    """Conversation model - represents a chat between multiple users."""
    __tablename__ = 'conversations'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=True)  # Optional group name
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    
    # Relationships
    messages = db.relationship('Message', backref='conversation', lazy='dynamic', cascade='all, delete-orphan')
    participants = db.relationship('ConversationParticipant', backref='conversation', lazy='dynamic', cascade='all, delete-orphan')
    keys = db.relationship('Key', backref='conversation', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Conversation {self.id}: {self.name or "Unnamed"}>'
    
    def to_dict(self):
        """Convert model to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'created_at': self.created_at.isoformat(),
            'participant_count': self.participants.count(),
            'message_count': self.messages.count()
        }


class ConversationParticipant(db.Model):
    """Association table for many-to-many relationship between Users and Conversations."""
    __tablename__ = 'conversation_participants'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    
    # Unique constraint to prevent duplicate participations
    __table_args__ = (db.UniqueConstraint('user_id', 'conversation_id', name='unique_user_conversation'),)
    
    def __repr__(self):
        return f'<ConversationParticipant user_id={self.user_id} conversation_id={self.conversation_id}>'
    
    def to_dict(self):
        """Convert model to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'conversation_id': self.conversation_id,
            'joined_at': self.joined_at.isoformat()
        }


class Message(db.Model):
    """Message model - stores individual messages in conversations."""
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False, index=True)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable=False)
    
    # Relationships
    files = db.relationship('File', backref='message', lazy='dynamic', cascade='all, delete-orphan')
    read_statuses = db.relationship('MessageReadStatus', backref='message', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Message {self.id} from user {self.user_id}>'
    
    def to_dict(self, include_read_status=False):
        """Convert model to dictionary."""
        result = {
            'id': self.id,
            'content': self.content,
            'user_id': self.user_id,
            'conversation_id': self.conversation_id,
            'created_at': self.created_at.isoformat(),
            'file_count': self.files.count()
        }
        
        if include_read_status:
            result['read_by'] = [rs.to_dict() for rs in self.read_statuses.all()]
            result['read_count'] = self.read_statuses.count()
        
        return result


class Key(db.Model):
    """Key model - stores encryption keys for each user in each conversation."""
    __tablename__ = 'keys'
    
    id = db.Column(db.Integer, primary_key=True)
    key_data = db.Column(db.String(500), nullable=False)  # Encrypted key material
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable=False)
    
    # Unique constraint - each user gets one key per conversation
    __table_args__ = (db.UniqueConstraint('user_id', 'conversation_id', name='unique_user_conversation_key'),)
    
    def __repr__(self):
        return f'<Key user_id={self.user_id} conversation_id={self.conversation_id}>'
    
    def to_dict(self):
        """Convert model to dictionary."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'conversation_id': self.conversation_id,
            'key_data': self.key_data,
            'created_at': self.created_at.isoformat()
        }


class File(db.Model):
    """File model - stores encrypted files attached to messages."""
    __tablename__ = 'files'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_data = db.Column(db.LargeBinary, nullable=False)  # Encrypted file content
    file_size = db.Column(db.Integer, nullable=False)  # Size in bytes
    mime_type = db.Column(db.String(100), nullable=True)  # e.g., 'image/png', 'application/pdf'
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    
    # Foreign key to Message
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    
    def __repr__(self):
        return f'<File {self.filename} in message {self.message_id}>'
    
    def to_dict(self, include_data=False):
        """Convert model to dictionary."""
        result = {
            'id': self.id,
            'filename': self.filename,
            'file_size': self.file_size,
            'mime_type': self.mime_type,
            'message_id': self.message_id,
            'created_at': self.created_at.isoformat()
        }
        
        # Only include encrypted data if explicitly requested
        if include_data:
            result['encrypted_data'] = self.encrypted_data.decode('latin-1') if self.encrypted_data else None
        
        return result


class MessageReadStatus(db.Model):
    """MessageReadStatus model - tracks which users have read which messages."""
    __tablename__ = 'message_read_statuses'
    
    id = db.Column(db.Integer, primary_key=True)
    read_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    
    # Foreign keys
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Unique constraint - each user can only mark a message as read once
    __table_args__ = (db.UniqueConstraint('message_id', 'user_id', name='unique_message_user_read'),)
    
    def __repr__(self):
        return f'<MessageReadStatus message_id={self.message_id} user_id={self.user_id}>'
    
    def to_dict(self):
        """Convert model to dictionary."""
        return {
            'id': self.id,
            'message_id': self.message_id,
            'user_id': self.user_id,
            'read_at': self.read_at.isoformat()
        }
