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

  // Auto-resize textarea
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 200) + 'px';
    }
  }, [inputValue]);

  // Handle send message
  const handleSend = () => {
    if (!inputValue.trim() || !isConnected) return;
    onSendMessage(inputValue);
    setInputValue('');
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }
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
            <div key={i} className="code-block my-3 overflow-hidden">
              {lang && (
                <div className="flex items-center justify-between px-4 py-2 border-b border-cyber-border bg-cyber-surface/50">
                  <span className="text-xs text-cyber-text-dim font-medium uppercase">{lang}</span>
                  <button 
                    onClick={() => navigator.clipboard.writeText(code)}
                    className="text-xs text-cyber-text-dim hover:text-cyber-accent transition-colors"
                  >
                    Copy
                  </button>
                </div>
              )}
              <pre className="p-4 overflow-x-auto">
                <code className="text-sm text-gemini-blue font-mono">{code}</code>
              </pre>
            </div>
          );
        }
      }
      
      // Regular text with markdown-like formatting
      return (
        <span key={i} className="whitespace-pre-wrap leading-relaxed">
          {part.split(/(\*\*.*?\*\*)/g).map((segment, j) => {
            if (segment.startsWith('**') && segment.endsWith('**')) {
              return <strong key={j} className="text-gemini-purple font-medium">{segment.slice(2, -2)}</strong>;
            }
            return segment;
          })}
        </span>
      );
    });
  };

  return (
    <div className="flex-1 flex flex-col" style={{ background: 'linear-gradient(180deg, #1e1f20 0%, #131314 100%)' }}>
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-cyber-border/50">
        <div className="flex items-center gap-4">
          <button
            onClick={onToggleSidebar}
            className="p-2.5 hover:bg-cyber-card rounded-xl transition-all duration-200"
            title={sidebarOpen ? 'Hide sidebar' : 'Show sidebar'}
          >
            <svg className="w-5 h-5 text-cyber-text-dim" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          <div className="flex items-center gap-2">
            <span className="text-2xl aegis-logo">🛡️</span>
            <h1 className="text-lg font-medium gradient-text">Aegis AI</h1>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className={`status-badge ${isConnected ? 'status-success' : 'status-error'}`}>
            <span className={`w-2 h-2 rounded-full mr-2 ${isConnected ? 'bg-cyber-success' : 'bg-cyber-error'}`}></span>
            {isConnected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-6 py-6">
        <div className="max-w-4xl mx-auto space-y-6">
          {messages.length === 0 && (
            <div className="flex flex-col items-center justify-center h-full text-center py-20">
              <div className="text-7xl mb-6 aegis-logo">🛡️</div>
              <h2 className="text-3xl font-semibold gradient-text mb-3">Welcome to Aegis AI</h2>
              <p className="text-cyber-text-dim max-w-lg text-lg leading-relaxed">
                Your autonomous penetration testing assistant. 
                Start by providing a target and mission rules.
              </p>
              <div className="mt-8 grid grid-cols-2 gap-4 max-w-md">
                <div className="card hover-lift cursor-pointer" onClick={() => onSendMessage("Start a penetration test on my application")}>
                  <span className="text-xl mb-2 block">🔍</span>
                  <span className="text-sm text-cyber-text-dim">Penetration Test</span>
                </div>
                <div className="card hover-lift cursor-pointer" onClick={() => onSendMessage("Help me solve a CTF challenge")}>
                  <span className="text-xl mb-2 block">🏁</span>
                  <span className="text-sm text-cyber-text-dim">CTF Mode</span>
                </div>
              </div>
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
                className={`max-w-3xl px-5 py-4 rounded-2xl ${
                  message.role === 'user'
                    ? 'message-user'
                    : message.role === 'system'
                    ? 'bg-cyber-warning/10 border border-cyber-warning/30'
                    : 'message-assistant'
                }`}
              >
                {message.role !== 'user' && (
                  <div className="flex items-center gap-2 mb-3">
                    <span className="text-lg">
                      {message.role === 'system' ? '⚙️' : '🛡️'}
                    </span>
                    <span className="text-xs font-medium text-cyber-text-dim uppercase tracking-wider">
                      {message.role === 'system' ? 'System' : 'Aegis AI'}
                    </span>
                  </div>
                )}
                <div className="text-[15px]">
                  {formatContent(message.content)}
                </div>
                <div className="text-xs text-cyber-text-dim mt-3 opacity-60">
                  {new Date(message.timestamp * 1000).toLocaleTimeString()}
                </div>
              </div>
            </div>
          ))}

          {/* Thinking indicator */}
          {isThinking && (
            <div className="flex justify-start">
              <div className="message-assistant rounded-2xl px-5 py-4 max-w-3xl">
                <div className="flex items-center gap-2 mb-3">
                  <span className="text-lg">🛡️</span>
                  <span className="text-xs font-medium text-cyber-text-dim uppercase tracking-wider">Aegis AI</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="typing-indicator">
                    <span></span>
                    <span></span>
                    <span></span>
                  </div>
                  <span className="text-sm text-cyber-text-dim">Analyzing...</span>
                </div>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>
      </div>

      {/* Input Area */}
      <div className="px-6 py-5 border-t border-cyber-border/50">
        <div className="max-w-4xl mx-auto">
          <div className="flex items-end gap-4">
            {/* File Upload Button */}
            <button
              onClick={() => fileInputRef.current?.click()}
              className="flex-shrink-0 p-3.5 bg-cyber-card border border-cyber-border/50 rounded-xl hover:border-gemini-blue/50 hover:bg-cyber-surface transition-all duration-200"
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
                placeholder={isConnected ? 'Enter a prompt here...' : 'Connecting...'}
                disabled={!isConnected}
                rows={1}
                className="w-full bg-cyber-card border border-cyber-border/50 rounded-2xl px-5 py-4 text-cyber-text placeholder-cyber-text-dim resize-none focus:outline-none focus:border-gemini-blue/50 focus:ring-2 focus:ring-gemini-blue/20 transition-all duration-200 disabled:opacity-50"
                style={{
                  minHeight: '56px',
                  maxHeight: '200px',
                }}
              />
            </div>

            {/* Send Button */}
            <button
              onClick={handleSend}
              disabled={!inputValue.trim() || !isConnected}
              className="flex-shrink-0 p-3.5 rounded-xl transition-all duration-200 disabled:opacity-30 disabled:cursor-not-allowed"
              style={{
                background: inputValue.trim() && isConnected 
                  ? 'linear-gradient(135deg, #8ab4f8 0%, #c58af9 100%)' 
                  : 'rgba(60, 64, 67, 0.5)'
              }}
            >
              <svg className="w-5 h-5 text-cyber-bg" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
              </svg>
            </button>
          </div>

          <p className="text-xs text-cyber-text-dim mt-3 text-center opacity-60">
            Press Enter to send • Shift+Enter for new line • Aegis AI may display inaccurate info, so double-check responses
          </p>
        </div>
      </div>
    </div>
  );
}
