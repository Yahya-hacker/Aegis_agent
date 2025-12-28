import { OperationMode } from '../App';

interface ConfigBarProps {
  currentMode: OperationMode;
  onModeChange: (mode: OperationMode) => void;
  onConnectMCP: () => void;
  mcpServerCount: number;
  isConnected: boolean;
}

const modes: Array<{ id: OperationMode; name: string; icon: string; color: string }> = [
  { id: 'penetration_testing', name: 'Pentest', icon: '🔓', color: '#8ab4f8' },
  { id: 'ctf_mode', name: 'CTF', icon: '🏁', color: '#fdd663' },
  { id: 'red_teaming', name: 'Red Team', icon: '🎯', color: '#f28b82' },
  { id: 'audit', name: 'Audit', icon: '📋', color: '#81c995' },
];

export default function ConfigBar({
  currentMode,
  onModeChange,
  onConnectMCP,
  mcpServerCount,
  isConnected,
}: ConfigBarProps) {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const currentModeData = modes.find(m => m.id === currentMode) || modes[0];

  return (
    <header className="border-b border-cyber-border/50 px-6 py-3" style={{ background: 'rgba(30, 31, 32, 0.95)' }}>
      <div className="flex items-center justify-between">
        {/* Logo and Title */}
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3">
            <span className="text-3xl aegis-logo">🛡️</span>
            <div>
              <h1 className="text-xl font-semibold gradient-text">Aegis AI</h1>
              <p className="text-[10px] text-cyber-text-dim uppercase tracking-wider">v9.1 Nexus Pro</p>
            </div>
          </div>

          {/* Connection Status */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full" style={{ background: isConnected ? 'rgba(129, 201, 149, 0.1)' : 'rgba(242, 139, 130, 0.1)' }}>
            <span
              className={`w-2 h-2 rounded-full ${
                isConnected ? 'bg-cyber-success' : 'bg-cyber-error'
              }`}
              style={{ boxShadow: isConnected ? '0 0 8px #81c995' : '0 0 8px #f28b82' }}
            />
            <span className={`text-xs font-medium ${isConnected ? 'text-cyber-success' : 'text-cyber-error'}`}>
              {isConnected ? 'Live' : 'Offline'}
            </span>
          </div>
        </div>

        {/* Mode Selector - Pill Style */}
        <div className="flex items-center gap-4">
          <div className="flex items-center p-1 rounded-full" style={{ background: 'rgba(40, 42, 44, 0.8)' }}>
            {modes.map((mode) => (
              <button
                key={mode.id}
                onClick={() => onModeChange(mode.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-full text-sm font-medium transition-all duration-200 ${
                  currentMode === mode.id
                    ? 'text-cyber-bg'
                    : 'text-cyber-text-dim hover:text-cyber-text'
                }`}
                style={{
                  background: currentMode === mode.id
                    ? `linear-gradient(135deg, ${mode.color} 0%, ${mode.color}99 100%)`
                    : 'transparent',
                  boxShadow: currentMode === mode.id ? `0 4px 15px ${mode.color}40` : 'none'
                }}
              >
                <span className="text-base">{mode.icon}</span>
                <span className="hidden sm:inline">{mode.name}</span>
              </button>
            ))}
          </div>

          {/* MCP Connect Button */}
          <button
            onClick={onConnectMCP}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl transition-all duration-200 hover-lift"
            style={{
              background: 'rgba(138, 180, 248, 0.1)',
              border: '1px solid rgba(138, 180, 248, 0.3)'
            }}
          >
            <svg className="w-5 h-5 text-gemini-blue" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
            </svg>
            <span className="text-sm text-gemini-blue font-medium">MCP</span>
            {mcpServerCount > 0 && (
              <span 
                className="flex items-center justify-center w-5 h-5 text-xs font-bold rounded-full"
                style={{ background: 'linear-gradient(135deg, #8ab4f8 0%, #c58af9 100%)', color: '#1e1f20' }}
              >
                {mcpServerCount}
              </span>
            )}
          </button>
        </div>
      </div>
    </header>
  );
}
