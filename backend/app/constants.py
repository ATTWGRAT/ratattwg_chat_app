"""Application constants and configuration values."""

# File upload limits
MAX_FILE_SIZE = 15 * 1024 * 1024  # 15MB in bytes

# Rate limiting
MAX_LOGIN_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 900  # 15 minutes in seconds

# Signature validation
SIGNATURE_MAX_AGE = 300  # 5 minutes for timestamp validation

# Pagination
DEFAULT_PAGE_SIZE = 20

# WebSocket events
WS_EVENT_FRIEND_REQUEST = 'friend_request_received'
WS_EVENT_FRIEND_ACCEPTED = 'friend_request_accepted'
WS_EVENT_FRIEND_REJECTED = 'friend_request_rejected'
WS_EVENT_MESSAGE_RECEIVED = 'message_received'
WS_EVENT_MESSAGE_DELETED = 'message_deleted'
WS_EVENT_MESSAGES_READ = 'messages_read'
WS_EVENT_FORCE_LOGOUT = 'force_logout'
WS_EVENT_USER_REGISTERED = 'user_registered'

# Error messages
ERROR_UNAUTHORIZED = "Unauthorized access"
ERROR_TIMESTAMP_EXPIRED = "Request timestamp expired"
ERROR_INVALID_TIMESTAMP = "Invalid timestamp format"
ERROR_INVALID_SIGNATURE = "Invalid signature"
ERROR_USER_NOT_FOUND = "User not found"
ERROR_MESSAGE_NOT_FOUND = "Message not found"
ERROR_FRIEND_REQUEST_NOT_FOUND = "Friend request not found"
ERROR_FRIENDSHIP_NOT_FOUND = "Friendship not found"
ERROR_CONVERSATION_KEY_NOT_FOUND = "Conversation key not found"
ERROR_INVALID_DATA = "Invalid request data"
ERROR_MISSING_FIELDS = "Missing required fields"
ERROR_EMAIL_REQUIRED = "Email is required"
ERROR_NO_DATA_PROVIDED = "No data provided"
ERROR_SIGNATURE_REQUIRED = "Signature, timestamp, and data are required"
ERROR_DUPLICATE_USERNAME = "Username already exists"
ERROR_DUPLICATE_EMAIL = "Email already exists"
ERROR_FRIEND_REQUEST_EXISTS = "Friend request already exists"
ERROR_ALREADY_FRIENDS = "Already friends with this user"
ERROR_SELF_FRIEND_REQUEST = "Cannot send friend request to yourself"
ERROR_NOT_CONVERSATION_MEMBER = "Not authorized for this conversation"
ERROR_NOT_MESSAGE_OWNER = "Not authorized to delete this message"
ERROR_INVALID_BASE64 = "Invalid base64 encoding"
ERROR_INVALID_IV_FORMAT = "Invalid IV format: must be 24 hex characters (12 bytes)"
ERROR_DUPLICATE_NONCE = "Nonce already used in this conversation"
ERROR_INVALID_2FA = "Invalid 2FA code"
ERROR_TOTP_REQUIRED = "TOTP code is required"
ERROR_NO_PENDING_REGISTRATION = "No pending registration found"
ERROR_REQUEST_ALREADY_PROCESSED = "Request is already processed"
ERROR_DATABASE_ERROR = "Database error"
ERROR_FAILED_TO_SEND = "Failed to send message"
ERROR_FAILED_TO_DELETE = "Failed to delete message"
ERROR_INVALID_BEFORE_TIMESTAMP = "Invalid before timestamp"
ERROR_NO_SIGNATURE_DATA = "No signature data provided"
ERROR_INVALID_SIGNATURE_FORMAT = "Invalid signature data format"
ERROR_DATA_FIELD_REQUIRED = "Data field is required"
ERROR_NOT_AUTHENTICATED = "Not authenticated"
ERROR_INVALID_CREDENTIALS = "Invalid credentials"
ERROR_INVALID_EMAIL = "Invalid email"
ERROR_INVALID_USERNAME = "Invalid username"
ERROR_EMAIL_OR_USERNAME_REQUIRED = "Email or username is required"
ERROR_PASSWORD_AND_TOTP_REQUIRED = "Password_hash and totp_code are required"
ERROR_PASSWORD_AND_RECOVERY_REQUIRED = "Password_hash and recovery_code are required"
ERROR_NO_2FA_RESET_REQUIRED = "No 2FA reset required"
ERROR_NO_PENDING_2FA_RESET = "No pending 2FA reset found"
ERROR_MESSAGE_IDS_MUST_BE_LIST = "message_ids must be a list"
ERROR_FAILED_TO_MARK_READ = "Failed to mark messages as read"
ERROR_CONVERSATION_ID_REQUIRED = "conversation_id is required"
ERROR_UNAUTHORIZED_ACCESS = "Not authorized for this conversation"
