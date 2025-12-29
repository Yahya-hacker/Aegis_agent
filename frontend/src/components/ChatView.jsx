import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Send, Plus, Wrench, ChevronDown, ChevronUp, Copy, Check, Upload, FileText, Image, Binary, Network, Loader2, X } from 'lucide-react';
import { cn } from '../lib/utils';
import { mockChatMessages } from '../data/mock';
import ModeSelector from './ModeSelector';
import NexusIcon from './NexusIcon';
import { ScrollArea } from './ui/scroll-area';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';
const WS_BASE = process.env.REACT_APP_WS_URL || 'ws://localhost:8000';

const ChatView = () => {
  const [messages, setMessages] = useState(mockChatMessages);
  const [inputValue, setInputValue] = useState('');
  const [selectedMode, setSelectedMode] = useState('pro');
  const [expandedReasoning, setExpandedReasoning] = useState({});
  const [isConnected, setIsConnected] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [showUploadMenu, setShowUploadMenu] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  
  const wsRef = useRef(null);
  const clientIdRef = useRef(`client-${Date.now()}`);
  const fileInputRef = useRef(null);
  const messagesEndRef = useRef(null);

  // Auto-scroll to bottom on new messages
  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  // WebSocket connection
  useEffect(() => {
    const connectWebSocket = () => {
      const ws = new WebSocket(`${WS_BASE}/ws/${clientIdRef.current}`);
      
      ws.onopen = () => {
        console.log('WebSocket connected');
        setIsConnected(true);
      };
      
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          handleWebSocketMessage(data);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };
      
      ws.onclose = () => {
        console.log('WebSocket disconnected');
        setIsConnected(false);
        // Attempt to reconnect after 3 seconds
        setTimeout(connectWebSocket, 3000);
      };
      
      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
      };
      
      wsRef.current = ws;
    };

    connectWebSocket();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const handleWebSocketMessage = useCallback((data) => {
    switch (data.type) {
      case 'chat_message':
        setMessages(prev => [...prev, data.message]);
        break;
      case 'mode_change':
        setSelectedMode(data.mode);
        break;
      case 'file_uploaded':
        setUploadedFiles(prev => [...prev, data.file]);
        break;
      case 'connected':
        console.log('Connected with client ID:', data.client_id);
        break;
      default:
        console.log('Unknown message type:', data.type);
    }
  }, []);

  const handleSend = async () => {
    if (!inputValue.trim()) return;
    
    const newMessage = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content: inputValue,
      timestamp: new Date().toISOString(),
      mode: selectedMode
    };
    
    setMessages(prev => [...prev, newMessage]);
    setInputValue('');
    
    // Send via WebSocket if connected
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        type: 'chat',
        content: inputValue,
        mode: selectedMode
      }));
    } else {
      // Fallback to REST API
      try {
        await fetch(`${API_BASE}/api/chat/message`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            command: inputValue,
            mode: selectedMode
          })
        });
      } catch (error) {
        console.error('Failed to send message:', error);
      }
    }
  };

  const handleFileUpload = async (event) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;
    
    setIsUploading(true);
    setShowUploadMenu(false);
    
    for (const file of files) {
      const formData = new FormData();
      formData.append('file', file);
      
      try {
        const response = await fetch(`${API_BASE}/api/upload`, {
          method: 'POST',
          body: formData
        });
        
        if (response.ok) {
          const result = await response.json();
          
          // Add system message about the upload
          const uploadMessage = {
            id: `msg-${Date.now()}`,
            role: 'system',
            content: `📎 File uploaded: ${file.name} (${result.category})`,
            timestamp: new Date().toISOString()
          };
          setMessages(prev => [...prev, uploadMessage]);
        }
      } catch (error) {
        console.error('Failed to upload file:', error);
      }
    }
    
    setIsUploading(false);
    // Reset file input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const toggleReasoning = (messageId) => {
    setExpandedReasoning(prev => ({
      ...prev,
      [messageId]: !prev[messageId]
    }));
  };

  const getFileIcon = (category) => {
    switch (category) {
      case 'binary': return Binary;
      case 'pcap': return Network;
      case 'screenshot': return Image;
      case 'document': return FileText;
      default: return FileText;
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Chat Header */}
      <div className="px-4 md:px-6 py-3 md:py-4 border-b border-zinc-800">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <NexusIcon size={28} />
            <div>
              <h1 className="text-base md:text-lg font-mono font-bold text-zinc-100">Mission Control</h1>
              <p className="text-zinc-500 font-mono text-[10px] md:text-xs">Autonomous Penetration Testing Interface</p>
            </div>
          </div>
          {/* Connection Status */}
          <div className={cn(
            "flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono",
            isConnected 
              ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400"
              : "bg-red-500/10 border border-red-500/30 text-red-400"
          )}>
            <div className={cn(
              "w-2 h-2 rounded-full",
              isConnected ? "bg-emerald-500 animate-pulse" : "bg-red-500"
            )} />
            {isConnected ? 'CONNECTED' : 'DISCONNECTED'}
          </div>
        </div>
      </div>

      {/* Messages Area */}
      <ScrollArea className="flex-1 p-4 md:p-6">
        <div className="space-y-4 md:space-y-6 max-w-4xl mx-auto">
          {messages.map((message) => (
            <MessageBubble 
              key={message.id} 
              message={message}
              isExpanded={expandedReasoning[message.id]}
              onToggleReasoning={() => toggleReasoning(message.id)}
            />
          ))}
          <div ref={messagesEndRef} />
        </div>
      </ScrollArea>

      {/* Input Area */}
      <div className="border-t border-zinc-800 p-3 md:p-4">
        <div className="max-w-4xl mx-auto">
          {/* Mode Selector */}
          <ModeSelector selectedMode={selectedMode} setSelectedMode={setSelectedMode} />
          
          {/* Uploaded Files Preview */}
          {uploadedFiles.length > 0 && (
            <div className="flex flex-wrap gap-2 mb-3">
              {uploadedFiles.slice(-3).map((file, idx) => {
                const FileIcon = getFileIcon(file.category);
                return (
                  <div 
                    key={idx}
                    className="flex items-center gap-2 px-3 py-1.5 bg-zinc-800 rounded-lg text-xs font-mono"
                  >
                    <FileIcon className="w-4 h-4 text-zinc-400" />
                    <span className="text-zinc-300 truncate max-w-[100px]">{file.name}</span>
                    <button 
                      onClick={() => setUploadedFiles(prev => prev.filter((_, i) => i !== idx))}
                      className="text-zinc-500 hover:text-zinc-300"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </div>
                );
              })}
            </div>
          )}
          
          {/* Input Container */}
          <div className="flex items-center gap-1 md:gap-2 bg-[#0a0a0a] border border-zinc-800 rounded-lg p-2">
            {/* Left Actions */}
            <div className="flex items-center gap-0.5 md:gap-1 relative">
              {/* File Upload Button */}
              <button 
                className="p-1.5 md:p-2 rounded-lg hover:bg-zinc-800 transition-colors group relative"
                title="Attach files (binaries, documents, PCAPs, screenshots)"
                onClick={() => setShowUploadMenu(!showUploadMenu)}
                disabled={isUploading}
              >
                {isUploading ? (
                  <Loader2 className="w-4 md:w-5 h-4 md:h-5 text-blue-500 animate-spin" />
                ) : (
                  <Plus className="w-4 md:w-5 h-4 md:h-5 text-zinc-500 group-hover:text-zinc-300" />
                )}
              </button>
              
              {/* Upload Menu Dropdown */}
              {showUploadMenu && (
                <div className="absolute bottom-full left-0 mb-2 bg-zinc-900 border border-zinc-700 rounded-lg shadow-xl p-2 min-w-[200px] z-50">
                  <div className="text-zinc-400 font-mono text-xs px-2 py-1 mb-1">Upload File</div>
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    accept=".exe,.elf,.bin,.dll,.so,.pdf,.doc,.docx,.txt,.md,.pcap,.pcapng,.cap,.png,.jpg,.jpeg,.gif,.webp,.bmp,.zip,.tar,.gz,.7z,.py,.js,.html,.css,.php,.rb,.go,.rs,.json,.xml,.yaml,.yml,.conf,.ini"
                    onChange={handleFileUpload}
                    className="hidden"
                    id="file-upload"
                  />
                  <label 
                    htmlFor="file-upload"
                    className="flex items-center gap-2 px-2 py-2 rounded hover:bg-zinc-800 cursor-pointer transition-colors"
                  >
                    <Upload className="w-4 h-4 text-blue-400" />
                    <span className="text-zinc-300 text-sm">Choose files...</span>
                  </label>
                  <div className="border-t border-zinc-700 mt-2 pt-2 px-2">
                    <div className="text-zinc-500 text-xs">
                      Supported: binaries, documents, PCAPs, screenshots, code
                    </div>
                  </div>
                </div>
              )}
              
              <button 
                className="p-1.5 md:p-2 rounded-lg hover:bg-zinc-800 transition-colors group"
                title="Manual tool call / MCP servers"
              >
                <Wrench className="w-4 md:w-5 h-4 md:h-5 text-zinc-500 group-hover:text-zinc-300" />
              </button>
            </div>

            {/* Text Input */}
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
              placeholder="Enter target or command..."
              className="flex-1 bg-transparent border-none outline-none text-zinc-100 font-mono text-xs md:text-sm placeholder:text-zinc-600 px-1 md:px-2"
            />

            {/* Send Button */}
            <button
              onClick={handleSend}
              disabled={!inputValue.trim()}
              className={cn(
                'p-1.5 md:p-2 rounded-lg transition-all duration-200',
                inputValue.trim() 
                  ? 'bg-blue-600 hover:bg-blue-500 text-white' 
                  : 'bg-zinc-800 text-zinc-600 cursor-not-allowed'
              )}
            >
              <Send className="w-4 md:w-5 h-4 md:h-5" />
            </button>
          </div>
        </div>
      </div>
      
      {/* Click outside to close upload menu */}
      {showUploadMenu && (
        <div 
          className="fixed inset-0 z-40" 
          onClick={() => setShowUploadMenu(false)}
        />
      )}
    </div>
  );
};

const MessageBubble = ({ message, isExpanded, onToggleReasoning }) => {
  const [copied, setCopied] = useState(false);
  const isUser = message.role === 'user';

  const handleCopy = () => {
    navigator.clipboard.writeText(message.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={cn('flex gap-3', isUser && 'justify-end')}>
      {!isUser && (
        <div className="flex-shrink-0">
          <NexusIcon size={32} />
        </div>
      )}
      
      <div className={cn('max-w-[80%]', isUser && 'order-first')}>
        {/* Main Message */}
        <div 
          className={cn(
            'rounded-lg p-4 font-mono text-sm',
            isUser 
              ? 'bg-blue-600/20 border border-blue-500/30 text-zinc-100' 
              : 'bg-[#0a0a0a] border border-zinc-800 text-zinc-300'
          )}
        >
          <p className="whitespace-pre-wrap">{message.content}</p>
          
          {/* Tool Calls */}
          {message.toolCalls && message.toolCalls.length > 0 && (
            <div className="mt-3 pt-3 border-t border-zinc-700/50">
              <p className="text-zinc-500 text-xs uppercase tracking-wider mb-2">Tool Calls</p>
              {message.toolCalls.map((tool, idx) => (
                <code 
                  key={idx}
                  className="block bg-zinc-900 px-3 py-2 rounded text-blue-400 text-xs"
                >
                  {tool}
                </code>
              ))}
            </div>
          )}
        </div>

        {/* Agent Reasoning Toggle */}
        {message.reasoning && (
          <div className="mt-2">
            <button
              onClick={onToggleReasoning}
              className="flex items-center gap-2 text-purple-400 hover:text-purple-300 transition-colors text-xs font-mono"
            >
              {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              Agent Reasoning
            </button>
            
            {isExpanded && (
              <div className="mt-2 p-3 bg-purple-500/10 border border-purple-500/30 rounded-lg">
                <p className="text-purple-200 font-mono text-xs leading-relaxed">
                  {message.reasoning}
                </p>
              </div>
            )}
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-2 mt-2">
          <button 
            onClick={handleCopy}
            className="p-1 rounded hover:bg-zinc-800 transition-colors"
            title="Copy message"
          >
            {copied ? (
              <Check className="w-4 h-4 text-emerald-500" />
            ) : (
              <Copy className="w-4 h-4 text-zinc-600 hover:text-zinc-400" />
            )}
          </button>
          <span className="text-zinc-600 font-mono text-xs">
            {new Date(message.timestamp).toLocaleTimeString()}
          </span>
        </div>
      </div>

      {isUser && (
        <div className="flex-shrink-0 w-8 h-8 rounded-full bg-zinc-800 flex items-center justify-center">
          <span className="text-zinc-400 font-mono text-sm">U</span>
        </div>
      )}
    </div>
  );
};

export default ChatView;
