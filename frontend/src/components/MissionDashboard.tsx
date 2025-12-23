import { ToolStatus, SwarmDecision, MCPServer } from '../App';

interface MissionDashboardProps {
  toolStatuses: ToolStatus[];
  swarmDecisions: SwarmDecision[];
  mcpServers: MCPServer[];
  onClose: () => void;
}

export default function MissionDashboard({
  toolStatuses,
  swarmDecisions,
  mcpServers,
  onClose,
}: MissionDashboardProps) {
  return (
    <aside className="w-80 bg-cyber-surface border-r border-cyber-border flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-cyber-border">
        <h2 className="text-lg font-semibold text-cyber-accent">Mission Dashboard</h2>
        <button
          onClick={onClose}
          className="p-1 hover:bg-cyber-card rounded-lg transition-colors"
        >
          <svg className="w-5 h-5 text-cyber-text-dim" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-6">
        {/* Tool Status Section */}
        <section>
          <h3 className="text-sm font-semibold text-cyber-text-dim uppercase tracking-wide mb-3">
            🔧 Tools State
          </h3>
          
          {toolStatuses.length === 0 ? (
            <div className="text-sm text-cyber-text-dim text-center py-4 bg-cyber-card rounded-lg">
              No active tools
            </div>
          ) : (
            <div className="space-y-2">
              {toolStatuses.map((tool) => (
                <div
                  key={tool.name}
                  className="bg-cyber-card border border-cyber-border rounded-lg p-3"
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      {/* Status Icon */}
                      {tool.status === 'running' ? (
                        <div className="spinner" />
                      ) : tool.status === 'completed' ? (
                        <span className="text-cyber-success">✓</span>
                      ) : tool.status === 'failed' ? (
                        <span className="text-cyber-error">✗</span>
                      ) : (
                        <span className="text-cyber-warning">○</span>
                      )}
                      <span className="text-sm font-medium text-cyber-text">
                        {tool.name}
                      </span>
                    </div>
                    <span className={`status-badge ${
                      tool.status === 'running' ? 'status-running' :
                      tool.status === 'completed' ? 'status-success' :
                      tool.status === 'failed' ? 'status-error' :
                      'status-pending'
                    }`}>
                      {tool.status}
                    </span>
                  </div>
                  
                  {/* Progress Bar */}
                  {tool.status === 'running' && tool.progress !== undefined && (
                    <div className="w-full bg-cyber-bg rounded-full h-1.5 overflow-hidden">
                      <div
                        className="bg-cyber-accent h-full transition-all duration-300"
                        style={{ width: `${tool.progress}%` }}
                      />
                    </div>
                  )}
                  
                  {/* Output Preview */}
                  {tool.output && (
                    <p className="text-xs text-cyber-text-dim mt-2 truncate">
                      {tool.output}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Swarm Monitor Section */}
        <section>
          <h3 className="text-sm font-semibold text-cyber-text-dim uppercase tracking-wide mb-3">
            🐝 Swarm Monitor
          </h3>
          
          {swarmDecisions.length === 0 ? (
            <div className="text-sm text-cyber-text-dim text-center py-4 bg-cyber-card rounded-lg">
              No swarm activity
            </div>
          ) : (
            <div className="space-y-2">
              {swarmDecisions.slice(-5).reverse().map((decision, i) => (
                <div
                  key={i}
                  className={`bg-cyber-card border rounded-lg p-3 ${
                    decision.persona === 'RED' ? 'border-swarm-red/50' :
                    decision.persona === 'BLUE' ? 'border-swarm-blue/50' :
                    'border-swarm-judge/50'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-xs font-bold uppercase ${
                      decision.persona === 'RED' ? 'text-swarm-red' :
                      decision.persona === 'BLUE' ? 'text-swarm-blue' :
                      'text-swarm-judge'
                    }`}>
                      {decision.persona === 'RED' ? '🔴 RED (Attacker)' :
                       decision.persona === 'BLUE' ? '🔵 BLUE (Defender)' :
                       '⚖️ JUDGE'}
                    </span>
                    {decision.riskScore !== undefined && (
                      <span className="text-xs text-cyber-text-dim">
                        Risk: {decision.riskScore.toFixed(1)}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-cyber-text line-clamp-2">
                    {decision.content}
                  </p>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* MCP Servers Section */}
        <section>
          <h3 className="text-sm font-semibold text-cyber-text-dim uppercase tracking-wide mb-3">
            🔌 MCP Servers
          </h3>
          
          {mcpServers.length === 0 ? (
            <div className="text-sm text-cyber-text-dim text-center py-4 bg-cyber-card rounded-lg">
              No MCP servers connected
            </div>
          ) : (
            <div className="space-y-2">
              {mcpServers.map((server) => (
                <div
                  key={server.name}
                  className="bg-cyber-card border border-cyber-border rounded-lg p-3"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium text-cyber-text">
                      {server.name}
                    </span>
                    <span className={`w-2 h-2 rounded-full ${
                      server.enabled ? 'bg-cyber-success' : 'bg-cyber-error'
                    }`} />
                  </div>
                  <p className="text-xs text-cyber-text-dim truncate mb-1">
                    {server.endpoint}
                  </p>
                  <p className="text-xs text-cyber-accent">
                    {server.tools.length} tools available
                  </p>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* Footer Stats */}
      <div className="p-4 border-t border-cyber-border bg-cyber-card">
        <div className="grid grid-cols-3 gap-2 text-center">
          <div>
            <p className="text-lg font-bold text-cyber-accent">
              {toolStatuses.filter(t => t.status === 'running').length}
            </p>
            <p className="text-xs text-cyber-text-dim">Active</p>
          </div>
          <div>
            <p className="text-lg font-bold text-cyber-success">
              {toolStatuses.filter(t => t.status === 'completed').length}
            </p>
            <p className="text-xs text-cyber-text-dim">Done</p>
          </div>
          <div>
            <p className="text-lg font-bold text-cyber-error">
              {toolStatuses.filter(t => t.status === 'failed').length}
            </p>
            <p className="text-xs text-cyber-text-dim">Failed</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
