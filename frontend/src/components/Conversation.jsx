/**
 * Conversation component - Encrypted messaging interface with infinite scroll
 */

import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { getMessages, sendMessage, getConversationKey, deleteMessage, markMessagesAsRead } from '../utils/api';
import { onMessageReceived, onMessageDeleted, onMessagesRead } from '../utils/socket';
import {
  generateMessageNonce,
  encryptMessage,
  decryptMessage,
  signMessage,
  verifyMessageSignature,
  encryptFile,
  decryptFile,
  bytesToHex,
  hexToBytes,
  decryptConversationKey
} from '../utils/crypto';
import { Button } from './ui/Button';
import { LoadingOverlay } from './ui/Spinner';
import { Avatar } from './ui/Avatar';
import { Alert } from './ui/Alert';

export default function Conversation({ 
  conversationId, 
  friend,
  userId, 
  privateKey, 
  masterKey,
  onBack 
}) {
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const [conversationKey, setConversationKey] = useState(null);
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  
  const messagesEndRef = useRef(null);
  const messagesContainerRef = useRef(null);
  const fileInputRef = useRef(null);
  const isInitialLoad = useRef(true);

  // Scroll to bottom helper
  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, []);

  // Decrypt and verify a message
  const decryptAndVerifyMessage = useCallback(async (msg, convKey) => {
    try {
      const nonce = hexToBytes(msg.nonce);
      const decryptedContent = await decryptMessage(
        msg.encrypted_content,
        convKey || conversationKey,
        nonce
      );
      
      // Verify signature
      const isValid = verifyMessageSignature(
        msg.sender.public_key,
        {
          encrypted_content: msg.encrypted_content,
          nonce: msg.nonce,
          conversation_id: conversationId
        },
        msg.signature
      );
      
      if (!isValid) {
        throw new Error('Invalid message signature');
      }
      
      // Decrypt attachments if present
      let decryptedAttachments = null;
      if (msg.attachments && msg.attachments.length > 0) {
        decryptedAttachments = await Promise.all(
          msg.attachments.map(async (att) => {
            const attNonce = hexToBytes(att.nonce);
            const decryptedData = await decryptFile(
              att.encrypted_data,
              convKey || conversationKey,
              attNonce
            );
            return {
              ...att,
              decryptedData,
              url: URL.createObjectURL(new Blob([decryptedData], { type: att.mime_type }))
            };
          })
        );
      }
      
      return {
        ...msg,
        content: decryptedContent,
        signatureValid: isValid,
        attachments: decryptedAttachments
      };
    } catch (err) {
      console.error('Failed to decrypt message:', err);
      return {
        ...msg,
        content: '[Failed to decrypt]',
        signatureValid: false,
        error: true
      };
    }
  }, [conversationKey, conversationId]);

  // Load conversation key and initial messages
  useEffect(() => {
    if (!conversationId) return;
    
    const loadConversation = async () => {
      setLoading(true);
      setError('');
      
      try {
        // Get encrypted conversation key
        const keyData = await getConversationKey(conversationId, privateKey);
        
        // Decrypt conversation key with master key
        const decrypted = await decryptConversationKey(
          keyData.encrypted,
          keyData.iv,
          masterKey
        );
        setConversationKey(decrypted);
        
        // Load initial messages
        const result = await getMessages(conversationId, privateKey);
        const decryptedMessages = await Promise.all(
          result.messages.map(async (msg) => await decryptAndVerifyMessage(msg, decrypted))
        );
        setMessages(decryptedMessages);
        setHasMore(result.has_more);
        
        // Scroll to bottom on initial load
        setTimeout(() => scrollToBottom(), 100);
      } catch (err) {
        console.error('Failed to load conversation:', err);
        setError(err.message || 'Failed to load conversation');
      } finally {
        setLoading(false);
        isInitialLoad.current = false;
      }
    };
    
    loadConversation();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [conversationId, privateKey, masterKey]);

  // Listen for new messages via WebSocket
  useEffect(() => {
    if (!conversationId || !conversationKey) return;

    const handleNewMessage = async (data) => {
      if (data.conversation_id !== conversationId) return;
      
      try {
        const decrypted = await decryptAndVerifyMessage(data.message, conversationKey);
        // Prevent duplicates: check if message already exists
        setMessages(prev => {
          const exists = prev.some(m => m.id === decrypted.id);
          if (exists) return prev;
          return [...prev, decrypted];
        });
        setTimeout(() => scrollToBottom(), 50);
      } catch (err) {
        console.error('Failed to decrypt incoming message:', err);
      }
    };
    
    onMessageReceived(handleNewMessage);
    
    // Listen for message deletions
    const handleMessageDeleted = (data) => {
      if (data.conversation_id !== conversationId) return;
      // Remove the deleted message from display
      setMessages(prev => prev.filter(msg => msg.id !== data.message_id));
    };
    
    onMessageDeleted(handleMessageDeleted);
    
    // Listen for read receipts
    const handleMessagesRead = (data) => {
      if (data.conversation_id !== conversationId) return;
      setMessages(prev => prev.map(msg => 
        data.message_ids.includes(msg.id) ? { ...msg, read_by_recipient: true } : msg
      ));
    };
    
    onMessagesRead(handleMessagesRead);
    
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [conversationId, conversationKey]);

  // Load more messages (infinite scroll)
  const loadMoreMessages = useCallback(async () => {
    if (loadingMore || !hasMore || messages.length === 0) return;
    
    setLoadingMore(true);
    try {
      const oldestMessage = messages[0];
      const result = await getMessages(
        conversationId,
        privateKey,
        oldestMessage.created_at,
        15
      );
      
      const decryptedMessages = await Promise.all(
        result.messages.map(async (msg) => await decryptAndVerifyMessage(msg, conversationKey))
      );
      
      setMessages(prev => [...decryptedMessages, ...prev]);
      setHasMore(result.has_more);
    } catch (err) {
      console.error('Failed to load more messages:', err);
    } finally {
      setLoadingMore(false);
    }
  }, [conversationId, privateKey, messages, conversationKey, hasMore, loadingMore, decryptAndVerifyMessage]);

  // Handle scroll for infinite loading
  const handleScroll = useCallback(() => {
    if (!messagesContainerRef.current) return;
    
    const { scrollTop } = messagesContainerRef.current;
    if (scrollTop === 0 && hasMore && !loadingMore) {
      loadMoreMessages();
    }
  }, [hasMore, loadingMore, loadMoreMessages]);

  // Send message with retry on nonce collision
  const handleSend = useCallback(async (e) => {
    e.preventDefault();
    
    if ((!newMessage.trim() && !selectedFile) || sending || !conversationKey) return;
    
    setSending(true);
    setError('');
    
    const MAX_RETRIES = 3;
    let attempt = 0;
    let fileData = null;
    
    // Read file once if present
    if (selectedFile) {
      fileData = await selectedFile.arrayBuffer();
    }
    
    while (attempt < MAX_RETRIES) {
      try {
        // Generate nonce (new one on each attempt)
        const nonce = generateMessageNonce();
        const nonceHex = bytesToHex(nonce);
        
        // Encrypt message
        const encryptedContent = await encryptMessage(
          newMessage.trim() || ' ',
          conversationKey,
          nonce
        );
        
        // Sign message
        const signature = signMessage(privateKey, {
          encrypted_content: encryptedContent,
          nonce: nonceHex,
          conversation_id: conversationId
        });
        
        const messageData = {
          conversation_id: conversationId,
          encrypted_content: encryptedContent,
          nonce: nonceHex,
          signature
        };
        
        // Handle file attachment with new nonce each attempt
        if (fileData) {
          const fileNonce = generateMessageNonce();
          const encryptedFileData = await encryptFile(fileData, conversationKey, fileNonce);
          
          messageData.attachment = {
            filename: selectedFile.name,
            encrypted_data: encryptedFileData,
            nonce: bytesToHex(fileNonce),
            original_size: selectedFile.size,
            mime_type: selectedFile.type
          };
        }
        
        // Send message
        await sendMessage(messageData, privateKey);
        
        // Success! Clear input
        setNewMessage('');
        setSelectedFile(null);
        if (fileInputRef.current) fileInputRef.current.value = '';
        
        // Note: New message will appear via WebSocket event
        break; // Exit retry loop on success
        
      } catch (err) {
        // Check if it's a nonce collision (409 Conflict)
        if (err.response?.status === 409 && attempt < MAX_RETRIES - 1) {
          attempt++;
          // Small delay before retry
          await new Promise(resolve => setTimeout(resolve, 100));
          continue;
        }
        
        // If not a nonce collision or out of retries, show error
        console.error('Failed to send message:', err);
        setError(err.response?.data?.error || err.message || 'Failed to send message');
        break;
      }
    }
    
    setSending(false);
  }, [newMessage, selectedFile, sending, conversationKey, conversationId, privateKey]);

  const handleFileSelect = useCallback((e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    // Check file size (15MB)
    if (file.size > 15 * 1024 * 1024) {
      setError('File too large. Maximum size is 15MB');
      e.target.value = '';
      return;
    }
    
    setSelectedFile(file);
    setError('');
  }, []);

  const removeSelectedFile = useCallback(() => {
    setSelectedFile(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  }, []);

  // Delete message handler
  const handleDeleteMessage = useCallback(async (messageId) => {
    try {
      await deleteMessage(messageId, privateKey);
      // Remove message from local state
      setMessages(prev => prev.filter(msg => msg.id !== messageId));
    } catch (err) {
      console.error('Failed to delete message:', err);
      setError(err.message || 'Failed to delete message');
    }
  }, [privateKey]);

  // Mark messages as read when viewing conversation
  useEffect(() => {
    if (!conversationId || messages.length === 0 || !privateKey || !userId) return;
    
    const unreadMessages = messages
      .filter(msg => msg.sender.id !== userId && !msg.read_by_me)
      .map(msg => msg.id);
    
    if (unreadMessages.length > 0) {
      markMessagesAsRead(conversationId, unreadMessages, privateKey)
        .catch(err => console.error('Failed to mark messages as read:', err));
    }
  }, [conversationId, messages, privateKey, userId]);

  // Memoize messages rendering
  const renderedMessages = useMemo(() => {
    return messages.map((msg) => {
      const isOwn = msg.sender.id === userId;
      return (
        <div
          key={msg.id}
          className={`flex ${isOwn ? 'justify-end' : 'justify-start'}`}
        >
          <div className={`max-w-[70%] ${isOwn ? 'bg-blue-500 text-white' : 'bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white'} rounded-2xl px-4 py-2`}>
            <div className="flex items-start gap-2">
              <p className="break-words flex-1">{msg.content}</p>
              {isOwn && (
                <button
                  onClick={() => handleDeleteMessage(msg.id)}
                  className="text-white/70 hover:text-white transition-colors flex-shrink-0 mt-0.5"
                  aria-label="Delete message"
                  title="Delete message"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                  </svg>
                </button>
              )}
            </div>
            {msg.attachments && msg.attachments.map((att, idx) => (
              <div key={idx} className="mt-2">
                {att.mime_type?.startsWith('image/') ? (
                  <img src={att.url} alt={att.filename} className="max-w-full rounded-lg" />
                ) : (
                  <a
                    href={att.url}
                    download={att.filename}
                    className="flex items-center gap-2 p-2 bg-black/10 rounded-lg hover:bg-black/20"
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    <span className="text-sm">{att.filename}</span>
                  </a>
                )}
              </div>
            ))}
            <p className="text-xs mt-1 opacity-70">
              {new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              {msg.error && ' ⚠️'}
              {isOwn && msg.read_by_recipient && <span className="ml-1">✓✓</span>}
            </p>
          </div>
        </div>
      );
    });
  }, [messages, userId, handleDeleteMessage]);

  if (loading) {
    return <LoadingOverlay />;
  }

  return (
    <div className="flex flex-col h-full bg-white dark:bg-gray-900">
      {/* Header */}
      <div className="flex items-center gap-3 p-4 border-b border-gray-200 dark:border-gray-700">
        <button
          onClick={onBack}
          className="p-2 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
          aria-label="Back to friends"
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
          </svg>
        </button>
        <Avatar name={friend.username} />
        <div>
          <h2 className="font-semibold text-gray-900 dark:text-white">{friend.username}</h2>
          <p className="text-xs text-gray-500 dark:text-gray-400">🔒 End-to-end encrypted</p>
        </div>
      </div>

      {/* Messages */}
      <div
        ref={messagesContainerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto p-4 space-y-3"
      >
        {loadingMore && (
          <div className="text-center py-2">
            <div className="inline-block animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
          </div>
        )}
        
        {messages.length === 0 && (
          <div className="flex items-center justify-center h-full">
            <div className="text-center text-gray-500 dark:text-gray-400">
              <svg className="w-16 h-16 mx-auto mb-4 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
              </svg>
              <p className="text-lg font-medium">No messages yet</p>
              <p className="text-sm mt-1">Start the conversation with {friend.username}</p>
            </div>
          </div>
        )}
        
        {renderedMessages}
        <div ref={messagesEndRef} />
      </div>

      {/* Error Display */}
      {error && (
        <div className="px-4 py-2">
          <Alert type="error" message={error} onClose={() => setError('')} />
        </div>
      )}

      {/* Selected File Preview */}
      {selectedFile && (
        <div className="px-4 py-2 bg-blue-50 dark:bg-blue-900/20 border-t border-blue-200 dark:border-blue-800 flex items-center gap-2">
          <svg className="w-5 h-5 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
          </svg>
          <span className="flex-1 text-sm text-blue-600 dark:text-blue-400">{selectedFile.name}</span>
          <button
            type="button"
            onClick={removeSelectedFile}
            className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-200"
            aria-label="Remove file"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* Input */}
      <form onSubmit={handleSend} className="border-t border-gray-200 dark:border-gray-700 p-4 flex gap-2">
        <input
          ref={fileInputRef}
          type="file"
          onChange={handleFileSelect}
          className="hidden"
          accept="*/*"
        />
        <button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          disabled={sending}
          className="p-2 text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors disabled:opacity-50"
          aria-label="Attach file"
        >
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
          </svg>
        </button>
        <input
          type="text"
          value={newMessage}
          onChange={(e) => setNewMessage(e.target.value)}
          placeholder="Type a message..."
          disabled={sending}
          className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 disabled:opacity-50"
        />
        <Button
          type="submit"
          disabled={sending || (!newMessage.trim() && !selectedFile)}
          loading={sending}
        >
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
          </svg>
        </Button>
      </form>
    </div>
  );
}
