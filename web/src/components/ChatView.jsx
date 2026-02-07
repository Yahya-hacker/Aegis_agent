import React, { useState, useEffect, useRef } from 'react';
import { Send, Plus, Globe, ChevronDown, Mic, Code, Search, Shield, FileText } from 'lucide-react';
import { cn } from '../lib/utils';
import { ScrollArea } from './ui/scroll-area';

// Aegis-themed action chips for security operations
const ACTION_CHIPS = [
  { id: 'recon', label: 'Recon', icon: Search },
  { id: 'exploit', label: 'Exploit', icon: Code },
  { id: 'analyze', label: 'Analyze', icon: Shield },
  { id: 'report', label: 'Report', icon: FileText },
];

// Available models for the selector
const MODELS = [
  { id: 'deepseek/deepseek-r1', name: 'DeepSeek R1', description: 'Reasoning & Coding', badge: null },
  { id: 'google/gemini-2.5-flash', name: 'Gemini 2.5 Flash', description: 'Fast Responses', badge: '⚡' },
  { id: 'google/gemini-2.5-pro', name: 'Gemini 2.5 Pro', description: 'Balanced', badge: null },
  { id: 'ollama/llama3', name: 'Llama 3 (Local)', description: 'Local Execution', badge: null },
];

const ChatView = () => {
  const [messages, setMessages] = useState([]);
  const [inputValue, setInputValue] = useState('');
  const [selectedModel, setSelectedModel] = useState(MODELS[0]);
  const [isModelSelectorOpen, setIsModelSelectorOpen] = useState(false);
  const [isMissionActive, setIsMissionActive] = useState(false);
  const scrollRef = useRef(null);
  const modelSelectorRef = useRef(null);

  // Get time-based greeting
  const getGreeting = () => {
    const hour = new Date().getHours();
    if (hour < 12) return 'Good Morning';
    if (hour < 18) return 'Good Afternoon';
    return 'Good Evening';
  };

  // Close model selector when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (modelSelectorRef.current && !modelSelectorRef.current.contains(event.target)) {
        setIsModelSelectorOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Connect to SSE Stream on mount
  useEffect(() => {
    const eventSource = new EventSource('/api/stream');

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleServerEvent(data);
      } catch (e) {
        console.error("Error parsing SSE:", e);
      }
    };

    eventSource.onerror = (err) => {
      console.error("EventSource failed:", err);
    };

    return () => {
      eventSource.close();
    };
  }, []);

  // Scroll to bottom on new message
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  const handleServerEvent = (event) => {
    const { type, content, timestamp } = event;

    setMessages(prev => {
      const lastMsg = prev[prev.length - 1];

      if (type === 'thinking' || type === 'thought') {
        if (lastMsg && lastMsg.role === 'assistant' && !lastMsg.isComplete) {
          return prev.map((msg, i) =>
            i === prev.length - 1 ? { ...msg, reasoning: content } : msg
          );
        }
      }

      if (type === 'action') {
        if (lastMsg && lastMsg.role === 'assistant' && !lastMsg.isComplete) {
          return prev.map((msg, i) =>
            i === prev.length - 1 ? {
              ...msg,
              toolCalls: [...(msg.toolCalls || []), content]
            } : msg
          );
        }
      }

      if (type === 'observation' || type === 'info' || type === 'error') {
        if (lastMsg && lastMsg.role === 'assistant' && !lastMsg.isComplete) {
          return prev.map((msg, i) =>
            i === prev.length - 1 ? { ...msg, content: content } : msg
          );
        }
      }

      if (type === 'status' && content === 'started') {
        setIsMissionActive(true);
        return [...prev, {
          id: `sys-${Date.now()}`,
          role: 'assistant',
          content: 'Mission started. Initializing protocols...',
          timestamp: timestamp,
          isComplete: false
        }];
      }

      if (type === 'status' && content === 'completed') {
        setIsMissionActive(false);
        return prev.map((msg, i) =>
          i === prev.length - 1 ? { ...msg, isComplete: true } : msg
        );
      }

      return prev;
    });

    if (type === 'thought' || type === 'observation') {
      setMessages(prev => [...prev, {
        id: `msg-${Date.now()}`,
        role: 'assistant',
        content: type === 'thought' ? `🤔 ${content}` : `👁️ ${content}`,
        timestamp: new Date().toISOString()
      }]);
    }
  };

  const handleSend = async () => {
    if (!inputValue.trim()) return;

    const newMessage = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content: inputValue,
      timestamp: new Date().toISOString()
    };

    setMessages(prev => [...prev, newMessage]);
    const input = inputValue;
    setInputValue('');

    try {
      if (input.startsWith('http')) {
        await fetch('/api/mission/start', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: input, model: selectedModel.id })
        });
      } else {
        await fetch('/api/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content: input, model: selectedModel.id })
        });
      }
    } catch (e) {
      console.error("Failed to send:", e);
    }
  };

  const handleChipClick = (chipId) => {
    const prompts = {
      recon: 'Perform reconnaissance on ',
      exploit: 'Find exploitable vulnerabilities in ',
      analyze: 'Analyze the security posture of ',
      report: 'Generate a security report for ',
    };
    setInputValue(prompts[chipId] || '');
  };

  const showGreeting = messages.length === 0;

  return (
    <div className="flex flex-col h-full bg-[#050505]">
      {/* Header Bar */}
      <div className="flex items-center justify-between px-6 py-3 border-b border-zinc-900">
        <div className="flex items-center gap-2">
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-sm font-mono font-semibold text-zinc-100">Aegis AI</span>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-xs font-mono text-zinc-500">
            <span className="opacity-70">◉</span>
            <span>{isMissionActive ? 'MISSION ACTIVE' : 'VAULT ACTIVE'}</span>
          </div>
          <button className="text-zinc-500 hover:text-zinc-300 transition-colors">
            <span className="text-lg">↗</span>
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 overflow-hidden">
        {showGreeting ? (
          /* Welcome Screen */
          <div className="flex flex-col items-center justify-center h-full px-6">
            {/* Large Greeting */}
            <h1 className="text-5xl md:text-6xl font-serif italic text-zinc-400 mb-4 tracking-tight">
              {getGreeting()}, <span className="text-zinc-300">Operator.</span>
            </h1>

            <p className="text-zinc-500 text-base mb-2">I am ready to execute your security operations.</p>
            <p className="text-zinc-600 text-sm mb-12">Enter a target URL, upload intel, or type to begin.</p>

            {/* Input Container */}
            <div className="w-full max-w-2xl">
              <div className="bg-[#0a0a0a] border border-zinc-800 rounded-2xl p-4 shadow-2xl">
                {/* Input Row */}
                <div className="flex items-center gap-3">
                  <input
                    type="text"
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                    placeholder="How can I help you today?"
                    className="flex-1 bg-transparent border-none outline-none text-zinc-100 text-base placeholder:text-zinc-600"
                  />
                </div>

                {/* Bottom Row: Actions + Model Selector */}
                <div className="flex items-center justify-between mt-4 pt-3 border-t border-zinc-800/50">
                  {/* Left: File/Globe buttons */}
                  <div className="flex items-center gap-1">
                    <button className="p-2 rounded-lg hover:bg-zinc-800 transition-colors group">
                      <Plus className="w-5 h-5 text-zinc-500 group-hover:text-zinc-300" />
                    </button>
                    <button className="p-2 rounded-lg hover:bg-zinc-800 transition-colors group">
                      <Globe className="w-5 h-5 text-zinc-500 group-hover:text-zinc-300" />
                    </button>
                  </div>

                  {/* Right: Model Selector + Mic */}
                  <div className="flex items-center gap-2">
                    {/* Model Selector Dropdown */}
                    <div className="relative" ref={modelSelectorRef}>
                      <button
                        onClick={() => setIsModelSelectorOpen(!isModelSelectorOpen)}
                        className="flex items-center gap-2 px-3 py-1.5 rounded-lg hover:bg-zinc-800 transition-colors text-sm text-zinc-400"
                      >
                        <span>{selectedModel.name}</span>
                        <ChevronDown className={cn("w-4 h-4 transition-transform", isModelSelectorOpen && "rotate-180")} />
                      </button>

                      {/* Dropdown Menu */}
                      {isModelSelectorOpen && (
                        <div className="absolute bottom-full mb-2 right-0 w-64 bg-[#0f0f0f] border border-zinc-800 rounded-xl shadow-2xl overflow-hidden z-50">
                          <div className="px-3 py-2 border-b border-zinc-800">
                            <span className="text-[10px] font-mono font-bold text-zinc-500 uppercase tracking-wider">MODEL SELECTION</span>
                          </div>
                          <div className="p-1">
                            {MODELS.map((model) => (
                              <button
                                key={model.id}
                                onClick={() => {
                                  setSelectedModel(model);
                                  setIsModelSelectorOpen(false);
                                }}
                                className={cn(
                                  "w-full flex items-center gap-3 p-2.5 rounded-lg text-left transition-all group",
                                  selectedModel.id === model.id
                                    ? "bg-zinc-900"
                                    : "hover:bg-zinc-900/50"
                                )}
                              >
                                <div className={cn(
                                  "w-4 h-4 rounded-full border-2 flex items-center justify-center",
                                  selectedModel.id === model.id
                                    ? "border-emerald-500 bg-emerald-500"
                                    : "border-zinc-600"
                                )}>
                                  {selectedModel.id === model.id && (
                                    <div className="w-1.5 h-1.5 rounded-full bg-white" />
                                  )}
                                </div>
                                <div className="flex-1">
                                  <div className="flex items-center gap-2">
                                    <span className={cn(
                                      "text-sm font-medium",
                                      selectedModel.id === model.id ? "text-zinc-100" : "text-zinc-400"
                                    )}>
                                      {model.name}
                                    </span>
                                    {model.badge && <span className="text-xs">{model.badge}</span>}
                                  </div>
                                  <p className="text-[11px] text-zinc-600">{model.description}</p>
                                </div>
                              </button>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Mic Button */}
                    <button className="p-2 rounded-lg hover:bg-zinc-800 transition-colors group">
                      <Mic className="w-5 h-5 text-zinc-500 group-hover:text-zinc-300" />
                    </button>
                  </div>
                </div>
              </div>

              {/* Action Chips */}
              <div className="flex items-center justify-center gap-2 mt-4">
                {ACTION_CHIPS.map((chip) => (
                  <button
                    key={chip.id}
                    onClick={() => handleChipClick(chip.id)}
                    className="px-4 py-2 rounded-full border border-zinc-800 bg-zinc-900/50 text-zinc-400 text-sm font-mono hover:bg-zinc-800 hover:text-zinc-200 transition-all"
                  >
                    {chip.label}
                  </button>
                ))}
              </div>

              {/* Disclaimer */}
              <p className="text-center text-xs text-zinc-600 font-mono mt-6">
                Aegis AI can make mistakes. Verify critical data.
              </p>
            </div>
          </div>
        ) : (
          /* Chat View */
          <ScrollArea className="h-full p-4 md:p-6">
            <div className="space-y-4 md:space-y-6 max-w-4xl mx-auto pb-32">
              {messages.map((message) => (
                <MessageBubble key={message.id} message={message} />
              ))}
              <div ref={scrollRef} />
            </div>

            {/* Floating Input - Shows when there are messages */}
            <div className="fixed bottom-0 left-16 right-0 p-4 bg-gradient-to-t from-[#050505] via-[#050505] to-transparent">
              <div className="max-w-2xl mx-auto">
                <div className="bg-[#0a0a0a] border border-zinc-800 rounded-2xl p-3 shadow-2xl">
                  <div className="flex items-center gap-3">
                    <button className="p-2 rounded-lg hover:bg-zinc-800 transition-colors">
                      <Plus className="w-5 h-5 text-zinc-500" />
                    </button>
                    <input
                      type="text"
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleSend()}
                      placeholder="Continue the operation..."
                      className="flex-1 bg-transparent border-none outline-none text-zinc-100 text-sm placeholder:text-zinc-600"
                    />
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setIsModelSelectorOpen(!isModelSelectorOpen)}
                        className="flex items-center gap-1 px-2 py-1 text-xs text-zinc-500 hover:text-zinc-300"
                      >
                        {selectedModel.name}
                        <ChevronDown className="w-3 h-3" />
                      </button>
                      <button
                        onClick={handleSend}
                        disabled={!inputValue.trim()}
                        className={cn(
                          'p-2 rounded-lg transition-all',
                          inputValue.trim()
                            ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                            : 'bg-zinc-800 text-zinc-600 cursor-not-allowed'
                        )}
                      >
                        <Send className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </ScrollArea>
        )}
      </div>
    </div>
  );
};

// Message Bubble Component
const MessageBubble = ({ message }) => {
  const isUser = message.role === 'user';

  return (
    <div className={cn('flex gap-3', isUser && 'justify-end')}>
      {!isUser && (
        <div className="w-8 h-8 rounded-full bg-emerald-600/20 flex items-center justify-center flex-shrink-0">
          <span className="text-emerald-400 text-sm">A</span>
        </div>
      )}
      <div className={cn(
        'max-w-[80%] rounded-2xl p-4 font-mono text-sm',
        isUser
          ? 'bg-zinc-800 text-zinc-100'
          : 'bg-[#0a0a0a] border border-zinc-800 text-zinc-300'
      )}>
        <p className="whitespace-pre-wrap">{message.content}</p>

        {message.reasoning && (
          <div className="mt-3 p-3 bg-zinc-900/50 rounded-lg text-xs text-zinc-500 italic border-l-2 border-emerald-600/50">
            {message.reasoning}
          </div>
        )}

        {message.toolCalls && message.toolCalls.length > 0 && (
          <div className="mt-3 space-y-2">
            {message.toolCalls.map((call, idx) => (
              <div key={idx} className="p-2 bg-zinc-900 rounded text-xs text-emerald-400 font-mono">
                🔧 {call}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ChatView;
