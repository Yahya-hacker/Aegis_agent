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
  const activeCount = toolStatuses.filter(t => t.status === 'running').length;
  const completedCount = toolStatuses.filter(t => t.status === 'completed').length;
  const failedCount = toolStatuses.filter(t => t.status === 'failed').length;
  const totalCount = activeCount + completedCount + failedCount;
  const progressPercent = totalCount > 0 ? ((completedCount + failedCount) / totalCount * 100) : 0;

  return (
    <aside 
      className="w-80 border-r border-cyber-border/50 flex flex-col overflow-hidden"
      style={{ background: 'linear-gradient(180deg, rgba(30, 31, 32, 0.98) 0%, rgba(19, 19, 20, 0.98) 100%)' }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-cyber-border/50">
        <div className="flex items-center gap-2">
          <span className="text-xl">📊</span>
          <h2 className="text-base font-semibold gradient-text">Mission Status</h2>
        </div>
        <button
          onClick={onClose}
          className="p-2 hover:bg-cyber-card rounded-xl transition-all duration-200"
        >
          <svg className="w-4 h-4 text-cyber-text-dim" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* Overall Progress */}
      {totalCount > 0 && (
        <div className="px-5 py-4 border-b border-cyber-border/30">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-cyber-text-dim">Overall Progress</span>
            <span className="text-sm font-medium text-gemini-blue">{Math.round(progressPercent)}%</span>
          </div>
          <div className="progress-bar">
            <div className="progress-bar-fill" style={{ width: `${progressPercent}%` }} />
          </div>
        </div>
      )}

      <div className="flex-1 overflow-y-auto px-5 py-4 space-y-6">
        {/* Tool Status Section */}
        <section>
          <h3 className="flex items-center gap-2 text-xs font-semibold text-cyber-text-dim uppercase tracking-wider mb-3">
            <span>🔧</span>
            <span>Tools</span>
            {activeCount > 0 && (
              <span className="ml-auto flex items-center gap-1">
                <span className="w-2 h-2 rounded-full bg-gemini-blue animate-pulse" />
                <span className="text-gemini-blue">{activeCount} active</span>
              </span>
            )}
          </h3>
          
          {toolStatuses.length === 0 ? (
            <div className="text-sm text-cyber-text-dim text-center py-6 card">
              <span className="text-2xl block mb-2">🔍</span>
              No active tools
            </div>
          ) : (
            <div className="space-y-2">
              {toolStatuses.map((tool) => (
                <div
                  key={tool.name}
                  className={`card transition-all duration-200 ${
                    tool.status === 'running' ? 'action-executing border-gemini-blue/30' : ''
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      {/* Status Icon */}
                      {tool.status === 'running' ? (
                        <div className="spinner" />
                      ) : tool.status === 'completed' ? (
                        <span className="w-5 h-5 flex items-center justify-center rounded-full bg-cyber-success/20 text-cyber-success text-xs">✓</span>
                      ) : tool.status === 'failed' ? (
                        <span className="w-5 h-5 flex items-center justify-center rounded-full bg-cyber-error/20 text-cyber-error text-xs">✗</span>
                      ) : (
                        <span className="w-5 h-5 flex items-center justify-center rounded-full bg-cyber-warning/20 text-cyber-warning text-xs">○</span>
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
                    <div className="progress-bar mt-2">
                      <div className="progress-bar-fill" style={{ width: `${tool.progress}%` }} />
                    </div>
                  )}
                  
                  {/* Output Preview */}
                  {tool.output && (
                    <p className="text-xs text-cyber-text-dim mt-2 truncate opacity-70">
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
          <h3 className="flex items-center gap-2 text-xs font-semibold text-cyber-text-dim uppercase tracking-wider mb-3">
            <span>🎭</span>
            <span>Swarm Debate</span>
          </h3>
          
          {swarmDecisions.length === 0 ? (
            <div className="text-sm text-cyber-text-dim text-center py-6 card">
              <span className="text-2xl block mb-2">🤖</span>
              No swarm activity
            </div>
          ) : (
            <div className="space-y-2">
              {swarmDecisions.slice(-5).reverse().map((decision, i) => (
                <div
                  key={i}
                  className={`p-3 rounded-xl transition-all duration-200 ${
                    decision.persona === 'RED' ? 'swarm-red' :
                    decision.persona === 'BLUE' ? 'swarm-blue' :
                    'swarm-judge'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className={`text-xs font-semibold uppercase tracking-wide ${
                      decision.persona === 'RED' ? 'text-swarm-red' :
                      decision.persona === 'BLUE' ? 'text-swarm-blue' :
                      'text-swarm-judge'
                    }`}>
                      {decision.persona === 'RED' ? '🔴 Attacker' :
                       decision.persona === 'BLUE' ? '🔵 Defender' :
                       '⚖️ Judge'}
                    </span>
                    {decision.riskScore !== undefined && (
                      <span className="text-[10px] text-cyber-text-dim px-2 py-0.5 rounded-full bg-cyber-bg/50">
                        Risk: {decision.riskScore.toFixed(1)}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-cyber-text leading-relaxed line-clamp-2">
                    {decision.content}
                  </p>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* MCP Servers Section */}
        <section>
          <h3 className="flex items-center gap-2 text-xs font-semibold text-cyber-text-dim uppercase tracking-wider mb-3">
            <span>🔌</span>
            <span>MCP Servers</span>
            {mcpServers.length > 0 && (
              <span className="ml-auto text-gemini-purple">{mcpServers.length}</span>
            )}
          </h3>
          
          {mcpServers.length === 0 ? (
            <div className="text-sm text-cyber-text-dim text-center py-6 card">
              <span className="text-2xl block mb-2">🔗</span>
              No MCP connections
            </div>
          ) : (
            <div className="space-y-2">
              {mcpServers.map((server) => (
                <div
                  key={server.name}
                  className="card hover-lift"
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-sm font-medium text-cyber-text">
                      {server.name}
                    </span>
                    <span 
                      className={`w-2.5 h-2.5 rounded-full ${server.enabled ? 'bg-cyber-success' : 'bg-cyber-error'}`}
                      style={{ boxShadow: server.enabled ? '0 0 8px #81c995' : '0 0 8px #f28b82' }}
                    />
                  </div>
                  <p className="text-xs text-cyber-text-dim truncate mb-1.5 opacity-70">
                    {server.endpoint}
                  </p>
                  <p className="text-xs text-gemini-blue font-medium">
                    {server.tools.length} tools available
                  </p>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* Footer Stats */}
      <div className="p-4 border-t border-cyber-border/50" style={{ background: 'rgba(40, 42, 44, 0.5)' }}>
        <div className="grid grid-cols-3 gap-3 text-center">
          <div className="py-2">
            <p className="text-xl font-semibold text-gemini-blue">
              {activeCount}
            </p>
            <p className="text-[10px] text-cyber-text-dim uppercase tracking-wide">Active</p>
          </div>
          <div className="py-2">
            <p className="text-xl font-semibold text-cyber-success">
              {completedCount}
            </p>
            <p className="text-[10px] text-cyber-text-dim uppercase tracking-wide">Done</p>
          </div>
          <div className="py-2">
            <p className="text-xl font-semibold text-cyber-error">
              {failedCount}
            </p>
            <p className="text-[10px] text-cyber-text-dim uppercase tracking-wide">Failed</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
