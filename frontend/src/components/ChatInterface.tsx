import { useState, useRef, useEffect, KeyboardEvent } from 'react';
import { Message } from '../App';

interface ChatInterfaceProps {
  messages: Message[];
  isThinking: boolean;
  isConnected: boolean;
  onSendMessage: (content: string) => void;
  onFileUpload: (file: File) => void;
  onToggleSidebar: () => void;
  sidebarOpen: boolean;
}

export default function ChatInterface({
  messages,
  isThinking,
  isConnected,
  onSendMessage,
  onFileUpload,
  onToggleSidebar,
  sidebarOpen,
}: ChatInterfaceProps) {
  const [inputValue, setInputValue] = useState('');
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Handle send message
  const handleSend = () => {
    if (!inputValue.trim() || !isConnected) return;
    onSendMessage(inputValue);
    setInputValue('');
  };

  // Handle keyboard shortcut
  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  // Handle file selection
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      onFileUpload(file);
      e.target.value = ''; // Reset input
    }
  };

  // Format message content with code blocks
  const formatContent = (content: string) => {
    // Split by code blocks
    const parts = content.split(/(```[\s\S]*?```)/g);
    
    return parts.map((part, i) => {
      if (part.startsWith('```')) {
        // Extract language and code
        const match = part.match(/```(\w*)\n?([\s\S]*?)```/);
        if (match) {
          const [, lang, code] = match;
          return (
            <pre key={i} className="bg-cyber-surface rounded-lg p-3 my-2 overflow-x-auto">
              {lang && <span className="text-xs text-cyber-text-dim mb-1 block">{lang}</span>}
              <code className="text-sm text-cyber-accent font-mono">{code}</code>
            </pre>
          );
        }
      }
      
      // Regular text with markdown-like formatting
      return (
        <span key={i} className="whitespace-pre-wrap">
          {part.split(/(\*\*.*?\*\*)/g).map((segment, j) => {
            if (segment.startsWith('**') && segment.endsWith('**')) {
              return <strong key={j} className="text-cyber-accent">{segment.slice(2, -2)}</strong>;
            }
            return segment;
          })}
        </span>
      );
    });
  };

  return (
    <div className="flex-1 flex flex-col bg-cyber-bg">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-cyber-border">
        <button
          onClick={onToggleSidebar}
          className="p-2 hover:bg-cyber-card rounded-lg transition-colors"
          title={sidebarOpen ? 'Hide sidebar' : 'Show sidebar'}
        >
          <svg className="w-5 h-5 text-cyber-text-dim" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
          </svg>
        </button>
        <span className="text-sm text-cyber-text-dim">
          {messages.length} messages
        </span>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-center">
            <div className="text-6xl mb-4">🛡️</div>
            <h2 className="text-2xl font-bold text-cyber-accent mb-2">Welcome to Aegis AI</h2>
            <p className="text-cyber-text-dim max-w-md">
              Your autonomous penetration testing assistant. Start by providing a target and mission rules.
            </p>
          </div>
        )}

        {messages.map((message) => (
          <div
            key={message.id}
            className={`chat-message flex ${
              message.role === 'user' ? 'justify-end' : 'justify-start'
            }`}
          >
            <div
              className={`max-w-3xl px-4 py-3 rounded-xl ${
                message.role === 'user'
                  ? 'bg-cyber-accent text-cyber-bg'
                  : message.role === 'system'
                  ? 'bg-cyber-warning/20 border border-cyber-warning/50 text-cyber-text'
                  : 'bg-cyber-card border border-cyber-border text-cyber-text'
              }`}
            >
              {message.role !== 'user' && (
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-lg">
                    {message.role === 'system' ? '⚙️' : '🤖'}
                  </span>
                  <span className="text-xs font-medium text-cyber-text-dim uppercase">
                    {message.role === 'system' ? 'System' : 'Aegis AI'}
                  </span>
                </div>
              )}
              <div className="text-sm leading-relaxed">
                {formatContent(message.content)}
              </div>
              <div className="text-xs text-cyber-text-dim mt-2 opacity-60">
                {new Date(message.timestamp * 1000).toLocaleTimeString()}
              </div>
            </div>
          </div>
        ))}

        {/* Thinking indicator */}
        {isThinking && (
          <div className="flex justify-start">
            <div className="bg-cyber-card border border-cyber-border rounded-xl px-4 py-3">
              <div className="flex items-center gap-2">
                <span className="text-lg">🤖</span>
                <span className="text-xs font-medium text-cyber-text-dim uppercase">Aegis AI</span>
              </div>
              <div className="typing-indicator mt-2">
                <span></span>
                <span></span>
                <span></span>
              </div>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <div className="p-4 border-t border-cyber-border">
        <div className="flex items-end gap-3">
          {/* File Upload Button */}
          <button
            onClick={() => fileInputRef.current?.click()}
            className="flex-shrink-0 p-3 bg-cyber-card border border-cyber-border rounded-xl hover:border-cyber-accent transition-colors"
            title="Upload file"
          >
            <svg className="w-5 h-5 text-cyber-text-dim" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
          </button>
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            onChange={handleFileChange}
            accept=".txt,.json,.xml,.html,.css,.js,.py,.php,.java,.c,.cpp,.h,.md,.yaml,.yml,.log,.csv,.sql,.sh,.rb,.go,.rs,.png,.jpg,.jpeg,.gif,.bmp,.svg,.pdf,.doc,.docx,.pcap,.pcapng"
          />

          {/* Text Input */}
          <div className="flex-1 relative">
            <textarea
              ref={textareaRef}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={isConnected ? 'Type a message...' : 'Connecting...'}
              disabled={!isConnected}
              rows={1}
              className="w-full bg-cyber-card border border-cyber-border rounded-xl px-4 py-3 text-cyber-text placeholder-cyber-text-dim resize-none focus:outline-none focus:border-cyber-accent transition-colors disabled:opacity-50"
              style={{
                minHeight: '48px',
                maxHeight: '200px',
              }}
            />
          </div>

          {/* Send Button */}
          <button
            onClick={handleSend}
            disabled={!inputValue.trim() || !isConnected}
            className="flex-shrink-0 p-3 bg-cyber-accent text-cyber-bg rounded-xl hover:bg-cyber-accent-dim transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
            </svg>
          </button>
        </div>

        <p className="text-xs text-cyber-text-dim mt-2 text-center">
          Press Enter to send, Shift+Enter for new line
        </p>
      </div>
    </div>
  );
}
