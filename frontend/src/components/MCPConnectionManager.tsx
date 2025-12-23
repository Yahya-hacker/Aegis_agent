import { useState } from 'react';
import { MCPServer } from '../App';

interface MCPConnectionManagerProps {
  servers: MCPServer[];
  onConnect: (name: string, endpoint: string) => void;
  onDisconnect: (serverName: string) => void;
  onClose: () => void;
}

export default function MCPConnectionManager({
  servers,
  onConnect,
  onDisconnect,
  onClose,
}: MCPConnectionManagerProps) {
  const [name, setName] = useState('');
  const [endpoint, setEndpoint] = useState('');
  const [isConnecting, setIsConnecting] = useState(false);

  const handleConnect = async () => {
    if (!name.trim() || !endpoint.trim()) return;
    
    setIsConnecting(true);
    try {
      await onConnect(name.trim(), endpoint.trim());
      setName('');
      setEndpoint('');
    } finally {
      setIsConnecting(false);
    }
  };

  // Example MCP server presets
  const presets = [
    {
      name: 'GitHub',
      endpoint: 'stdio:npx @modelcontextprotocol/server-github',
      description: 'Access GitHub repositories and issues',
    },
    {
      name: 'Filesystem',
      endpoint: 'stdio:npx @modelcontextprotocol/server-filesystem /tmp',
      description: 'Browse and read local files',
    },
    {
      name: 'Brave Search',
      endpoint: 'stdio:npx @modelcontextprotocol/server-brave-search',
      description: 'Search the web with Brave',
    },
  ];

  return (
    <div className="modal-backdrop flex items-center justify-center p-4">
      <div className="bg-cyber-surface border border-cyber-border rounded-2xl w-full max-w-2xl max-h-[80vh] overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-cyber-border">
          <div>
            <h2 className="text-xl font-bold text-cyber-accent">MCP Connection Manager</h2>
            <p className="text-sm text-cyber-text-dim">
              Connect to Model Context Protocol servers to add external tools
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-cyber-card rounded-lg transition-colors"
          >
            <svg className="w-6 h-6 text-cyber-text-dim" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-6 overflow-y-auto max-h-[calc(80vh-120px)]">
          {/* Add New Server Form */}
          <div className="bg-cyber-card border border-cyber-border rounded-xl p-4 mb-6">
            <h3 className="text-lg font-semibold text-cyber-text mb-4">
              Add New MCP Server
            </h3>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-cyber-text-dim mb-1">
                  Server Name
                </label>
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g., My Custom Tools"
                  className="input-field"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-cyber-text-dim mb-1">
                  Endpoint URL
                </label>
                <input
                  type="text"
                  value={endpoint}
                  onChange={(e) => setEndpoint(e.target.value)}
                  placeholder="sse://localhost:3000/mcp or stdio:command"
                  className="input-field"
                />
                <p className="text-xs text-cyber-text-dim mt-1">
                  Supports SSE (sse://...) or stdio (stdio:command) transports
                </p>
              </div>

              <button
                onClick={handleConnect}
                disabled={!name.trim() || !endpoint.trim() || isConnecting}
                className="w-full btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isConnecting ? (
                  <span className="flex items-center justify-center gap-2">
                    <div className="spinner" />
                    Connecting...
                  </span>
                ) : (
                  'Connect Server'
                )}
              </button>
            </div>
          </div>

          {/* Quick Connect Presets */}
          <div className="mb-6">
            <h3 className="text-lg font-semibold text-cyber-text mb-3">
              Quick Connect
            </h3>
            <div className="grid grid-cols-1 gap-3">
              {presets.map((preset) => (
                <button
                  key={preset.name}
                  onClick={() => {
                    setName(preset.name);
                    setEndpoint(preset.endpoint);
                  }}
                  className="flex items-start gap-3 p-3 bg-cyber-card border border-cyber-border rounded-lg hover:border-cyber-accent transition-colors text-left"
                >
                  <div className="flex-shrink-0 w-10 h-10 bg-cyber-accent/20 rounded-lg flex items-center justify-center">
                    <svg className="w-5 h-5 text-cyber-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                    </svg>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-cyber-text">{preset.name}</p>
                    <p className="text-xs text-cyber-text-dim">{preset.description}</p>
                    <p className="text-xs text-cyber-accent truncate mt-1">{preset.endpoint}</p>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Connected Servers */}
          <div>
            <h3 className="text-lg font-semibold text-cyber-text mb-3">
              Connected Servers ({servers.length})
            </h3>
            
            {servers.length === 0 ? (
              <div className="text-center py-8 bg-cyber-card border border-cyber-border rounded-lg">
                <svg className="w-12 h-12 mx-auto text-cyber-text-dim mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 12h14M12 5l7 7-7 7" />
                </svg>
                <p className="text-cyber-text-dim">No MCP servers connected</p>
                <p className="text-xs text-cyber-text-dim mt-1">
                  Connect a server above to add external tools
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {servers.map((server) => (
                  <div
                    key={server.name}
                    className="bg-cyber-card border border-cyber-border rounded-lg p-4"
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span className={`w-2 h-2 rounded-full ${
                          server.enabled ? 'bg-cyber-success' : 'bg-cyber-error'
                        }`} />
                        <span className="font-medium text-cyber-text">{server.name}</span>
                      </div>
                      <button
                        onClick={() => onDisconnect(server.name)}
                        className="text-xs text-cyber-error hover:underline"
                      >
                        Disconnect
                      </button>
                    </div>
                    
                    <p className="text-xs text-cyber-text-dim truncate mb-2">
                      {server.endpoint}
                    </p>
                    
                    {server.tools.length > 0 && (
                      <div className="mt-3 pt-3 border-t border-cyber-border">
                        <p className="text-xs font-medium text-cyber-text-dim mb-2">
                          Available Tools ({server.tools.length})
                        </p>
                        <div className="flex flex-wrap gap-1">
                          {server.tools.slice(0, 5).map((tool) => (
                            <span
                              key={tool.name}
                              className="px-2 py-1 bg-cyber-surface text-xs text-cyber-accent rounded"
                              title={tool.description}
                            >
                              {tool.name}
                            </span>
                          ))}
                          {server.tools.length > 5 && (
                            <span className="px-2 py-1 text-xs text-cyber-text-dim">
                              +{server.tools.length - 5} more
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
