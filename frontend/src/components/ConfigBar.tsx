import { OperationMode } from '../App';

interface ConfigBarProps {
  currentMode: OperationMode;
  onModeChange: (mode: OperationMode) => void;
  onConnectMCP: () => void;
  mcpServerCount: number;
  isConnected: boolean;
}

const modes: Array<{ id: OperationMode; name: string; icon: string }> = [
  { id: 'penetration_testing', name: 'Penetration Testing', icon: '🔓' },
  { id: 'ctf_mode', name: 'CTF Mode', icon: '🚩' },
  { id: 'red_teaming', name: 'Red Teaming', icon: '🎯' },
  { id: 'audit', name: 'Security Audit', icon: '📋' },
];

export default function ConfigBar({
  currentMode,
  onModeChange,
  onConnectMCP,
  mcpServerCount,
  isConnected,
}: ConfigBarProps) {
  return (
    <header className="bg-cyber-surface border-b border-cyber-border px-4 py-3">
      <div className="flex items-center justify-between">
        {/* Logo and Title */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-2xl">🛡️</span>
            <div>
              <h1 className="text-xl font-bold text-cyber-accent">Aegis AI</h1>
              <p className="text-xs text-cyber-text-dim">v9.0 Nexus</p>
            </div>
          </div>

          {/* Connection Status */}
          <div className="flex items-center gap-2 ml-4">
            <span
              className={`w-2 h-2 rounded-full ${
                isConnected ? 'bg-cyber-success animate-pulse' : 'bg-cyber-error'
              }`}
            />
            <span className="text-xs text-cyber-text-dim">
              {isConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>

        {/* Mode Selector */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-cyber-text-dim">Mode:</span>
            <div className="relative">
              <select
                value={currentMode}
                onChange={(e) => onModeChange(e.target.value as OperationMode)}
                className="appearance-none bg-cyber-card border border-cyber-border rounded-lg px-4 py-2 pr-10 text-cyber-text text-sm focus:outline-none focus:border-cyber-accent cursor-pointer"
              >
                {modes.map((mode) => (
                  <option key={mode.id} value={mode.id}>
                    {mode.icon} {mode.name}
                  </option>
                ))}
              </select>
              <div className="absolute inset-y-0 right-0 flex items-center pr-3 pointer-events-none">
                <svg className="w-4 h-4 text-cyber-text-dim" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </div>
            </div>
          </div>

          {/* MCP Connect Button */}
          <button
            onClick={onConnectMCP}
            className="flex items-center gap-2 px-4 py-2 bg-cyber-card border border-cyber-border rounded-lg hover:border-cyber-accent transition-colors"
          >
            <svg className="w-5 h-5 text-cyber-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
            </svg>
            <span className="text-sm">Connect MCP</span>
            {mcpServerCount > 0 && (
              <span className="flex items-center justify-center w-5 h-5 text-xs font-bold bg-cyber-accent text-cyber-bg rounded-full">
                {mcpServerCount}
              </span>
            )}
          </button>
        </div>
      </div>
    </header>
  );
}
