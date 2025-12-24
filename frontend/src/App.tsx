import { useState, useEffect, useCallback } from 'react';
import ConfigBar from './components/ConfigBar';
import ChatInterface from './components/ChatInterface';
import MissionDashboard from './components/MissionDashboard';
import MCPConnectionManager from './components/MCPConnectionManager';
import { useWebSocket } from './hooks/useWebSocket';

// Types
export interface Message {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: number;
}

export interface ToolStatus {
  name: string;
  status: 'running' | 'completed' | 'failed' | 'pending';
  progress?: number;
  output?: string;
}

export interface SwarmDecision {
  persona: 'RED' | 'BLUE' | 'JUDGE';
  content: string;
  riskScore?: number;
  timestamp: number;
}

export interface MCPServer {
  name: string;
  endpoint: string;
  enabled: boolean;
  tools: Array<{ name: string; description: string }>;
}

export type OperationMode = 'penetration_testing' | 'ctf_mode' | 'red_teaming' | 'audit';

function App() {
  // State
  const [messages, setMessages] = useState<Message[]>([]);
  const [currentMode, setCurrentMode] = useState<OperationMode>('penetration_testing');
  const [toolStatuses, setToolStatuses] = useState<ToolStatus[]>([]);
  const [swarmDecisions, setSwarmDecisions] = useState<SwarmDecision[]>([]);
  const [mcpServers, setMcpServers] = useState<MCPServer[]>([]);
  const [showMCPModal, setShowMCPModal] = useState(false);
  const [isThinking, setIsThinking] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  
  // Determine WebSocket URL based on protocol (wss for https, ws for http)
  const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${wsProtocol}//${window.location.host}/ws/chat`;
  
  // WebSocket connection
  const { sendMessage, isConnected: wsConnected } = useWebSocket({
    url: wsUrl,
    onMessage: handleWebSocketMessage,
    onConnect: () => setIsConnected(true),
    onDisconnect: () => setIsConnected(false),
  });

  // Handle incoming WebSocket messages
  function handleWebSocketMessage(data: Record<string, unknown>) {
    switch (data.type) {
      case 'chat':
        const newMessage: Message = {
          id: crypto.randomUUID(),
          role: data.role as 'user' | 'assistant' | 'system',
          content: data.content as string,
          timestamp: data.timestamp as number || Date.now() / 1000,
        };
        setMessages((prev) => [...prev, newMessage]);
        break;

      case 'thinking':
        setIsThinking(data.status as boolean);
        break;

      case 'tool_status':
        updateToolStatus(data.tool as ToolStatus);
        break;

      case 'swarm_decision':
        addSwarmDecision(data as unknown as SwarmDecision);
        break;

      case 'mode_change':
        setCurrentMode(data.mode as OperationMode);
        break;

      case 'mcp_connected':
        fetchMCPServers();
        break;

      case 'mcp_disconnected':
        fetchMCPServers();
        break;

      case 'error':
        console.error('Server error:', data.message);
        break;
    }
  }

  // Update tool status
  const updateToolStatus = useCallback((tool: ToolStatus) => {
    setToolStatuses((prev) => {
      const existing = prev.findIndex((t) => t.name === tool.name);
      if (existing >= 0) {
        const updated = [...prev];
        updated[existing] = tool;
        return updated;
      }
      return [...prev, tool];
    });
  }, []);

  // Add swarm decision
  const addSwarmDecision = useCallback((decision: SwarmDecision) => {
    setSwarmDecisions((prev) => [...prev.slice(-19), decision]);
  }, []);

  // Send chat message
  const handleSendMessage = useCallback((content: string) => {
    if (!content.trim() || !wsConnected) return;

    sendMessage({
      type: 'chat',
      content: content.trim(),
    });
  }, [sendMessage, wsConnected]);

  // Change operation mode
  const handleModeChange = useCallback(async (mode: OperationMode) => {
    try {
      const response = await fetch(`/api/modes/${mode}`, { method: 'POST' });
      if (response.ok) {
        setCurrentMode(mode);
      }
    } catch (error) {
      console.error('Failed to change mode:', error);
    }
  }, []);

  // Fetch MCP servers
  const fetchMCPServers = useCallback(async () => {
    try {
      const response = await fetch('/api/mcp/servers');
      if (response.ok) {
        const data = await response.json();
        setMcpServers(data.servers);
      }
    } catch (error) {
      console.error('Failed to fetch MCP servers:', error);
    }
  }, []);

  // Connect to MCP server
  const handleConnectMCP = useCallback(async (name: string, endpoint: string) => {
    try {
      const response = await fetch('/api/mcp/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, endpoint, enabled: true }),
      });
      
      if (response.ok) {
        await fetchMCPServers();
        setShowMCPModal(false);
      } else {
        // Sanitize error message - only show safe, generic error
        alert('Failed to connect to MCP server. Please check the endpoint and try again.');
      }
    } catch (error) {
      console.error('Failed to connect MCP server:', error);
      alert('Failed to connect to MCP server. Please check your connection.');
    }
  }, [fetchMCPServers]);

  // Disconnect MCP server
  const handleDisconnectMCP = useCallback(async (serverName: string) => {
    try {
      const response = await fetch(`/api/mcp/servers/${serverName}`, {
        method: 'DELETE',
      });
      
      if (response.ok) {
        await fetchMCPServers();
      }
    } catch (error) {
      console.error('Failed to disconnect MCP server:', error);
    }
  }, [fetchMCPServers]);

  // File upload handler
  const handleFileUpload = useCallback(async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      if (response.ok) {
        const data = await response.json();
        // Send message about uploaded file
        handleSendMessage(`[File uploaded: ${data.filename}]`);
      } else {
        // Sanitize error message
        alert('Upload failed. Please check the file type and try again.');
      }
    } catch (error) {
      console.error('File upload failed:', error);
      alert('File upload failed. Please try again.');
    }
  }, [handleSendMessage]);

  // Load initial data
  useEffect(() => {
    fetchMCPServers();

    // Load chat history
    fetch('/api/chat/history')
      .then((res) => res.json())
      .then((data) => {
        const history = data.messages.map((m: Record<string, unknown>) => ({
          id: crypto.randomUUID(),
          role: m.role as 'user' | 'assistant' | 'system',
          content: m.content as string,
          timestamp: m.timestamp as number,
        }));
        setMessages(history);
      })
      .catch(console.error);

    // Load current mode
    fetch('/api/modes')
      .then((res) => res.json())
      .then((data) => setCurrentMode(data.current as OperationMode))
      .catch(console.error);
  }, [fetchMCPServers]);

  return (
    <div className="flex flex-col h-screen bg-cyber-bg">
      {/* Config Bar */}
      <ConfigBar
        currentMode={currentMode}
        onModeChange={handleModeChange}
        onConnectMCP={() => setShowMCPModal(true)}
        mcpServerCount={mcpServers.length}
        isConnected={isConnected}
      />

      {/* Main Content */}
      <div className="flex flex-1 overflow-hidden">
        {/* Mission Dashboard (Sidebar) */}
        {sidebarOpen && (
          <MissionDashboard
            toolStatuses={toolStatuses}
            swarmDecisions={swarmDecisions}
            mcpServers={mcpServers}
            onClose={() => setSidebarOpen(false)}
          />
        )}

        {/* Chat Interface (Central) */}
        <ChatInterface
          messages={messages}
          isThinking={isThinking}
          isConnected={isConnected}
          onSendMessage={handleSendMessage}
          onFileUpload={handleFileUpload}
          onToggleSidebar={() => setSidebarOpen(!sidebarOpen)}
          sidebarOpen={sidebarOpen}
        />
      </div>

      {/* MCP Connection Manager Modal */}
      {showMCPModal && (
        <MCPConnectionManager
          servers={mcpServers}
          onConnect={handleConnectMCP}
          onDisconnect={handleDisconnectMCP}
          onClose={() => setShowMCPModal(false)}
        />
      )}
    </div>
  );
}

export default App;
