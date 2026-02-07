// Mock data for Nexus Cybersecurity Command Center

export const mockMissions = [
  {
    id: 'mission-001',
    name: 'Reconnaissance Alpha',
    status: 'completed',
    startTime: '2025-07-15T08:30:00Z',
    endTime: '2025-07-15T09:45:00Z',
    tokensUsed: 15420,
    computeTime: 75,
    toolsUsed: ['nmap', 'whois', 'dig']
  },
  {
    id: 'mission-002',
    name: 'Vulnerability Scan Beta',
    status: 'completed',
    startTime: '2025-07-15T10:00:00Z',
    endTime: '2025-07-15T11:30:00Z',
    tokensUsed: 28750,
    computeTime: 90,
    toolsUsed: ['sqlmap', 'nikto', 'nmap']
  },
  {
    id: 'mission-003',
    name: 'Deep Analysis Gamma',
    status: 'active',
    startTime: '2025-07-15T12:00:00Z',
    endTime: null,
    tokensUsed: 42100,
    computeTime: 120,
    toolsUsed: ['burpsuite', 'sqlmap', 'metasploit', 'nmap']
  }
];

export const mockTelemetryData = [
  { time: '00:00', responseTime: 120, toolExecution: 45 },
  { time: '04:00', responseTime: 95, toolExecution: 38 },
  { time: '08:00', responseTime: 180, toolExecution: 72 },
  { time: '12:00', responseTime: 250, toolExecution: 95 },
  { time: '16:00', responseTime: 210, toolExecution: 88 },
  { time: '20:00', responseTime: 145, toolExecution: 52 },
  { time: '24:00', responseTime: 110, toolExecution: 42 }
];

export const mockToolDistribution = [
  { name: 'nmap', count: 145, fill: '#3b82f6' },
  { name: 'sqlmap', count: 98, fill: '#a855f7' },
  { name: 'nikto', count: 67, fill: '#3b82f6' },
  { name: 'burpsuite', count: 54, fill: '#a855f7' },
  { name: 'metasploit', count: 42, fill: '#3b82f6' },
  { name: 'whois', count: 38, fill: '#a855f7' },
  { name: 'dig', count: 29, fill: '#3b82f6' }
];

export const mockResourceStats = {
  totalTokens: 86270,
  totalComputeTime: 285,
  activeMissions: 1,
  completedMissions: 2
};

export const mockChatMessages = [
  {
    id: 'msg-001',
    role: 'user',
    content: 'Scan the target domain example.com for open ports and potential vulnerabilities.',
    timestamp: '2025-07-15T12:00:00Z'
  },
  {
    id: 'msg-002',
    role: 'assistant',
    content: 'Initiating reconnaissance on example.com. Running nmap scan with service detection enabled.',
    timestamp: '2025-07-15T12:00:15Z',
    reasoning: 'The target domain requires a comprehensive port scan to identify potential entry points. I will use nmap with -sV flag for service version detection and -sC for default scripts. This approach balances thoroughness with stealth.',
    toolCalls: ['nmap -sV -sC example.com']
  },
  {
    id: 'msg-003',
    role: 'assistant',
    content: 'Scan complete. Found 3 open ports:\n- Port 22 (SSH) - OpenSSH 8.4\n- Port 80 (HTTP) - nginx 1.21.0\n- Port 443 (HTTPS) - nginx 1.21.0\n\nPotential vulnerability detected: nginx version may be susceptible to CVE-2021-23017.',
    timestamp: '2025-07-15T12:02:30Z',
    reasoning: 'The nmap scan revealed standard web server configuration with SSH access. The nginx version 1.21.0 has known vulnerabilities. Recommending further analysis with nikto for web-specific vulnerabilities.',
    toolCalls: ['nikto -h example.com']
  }
];

export const mockMemoryEntries = [
  {
    id: 'mem-001',
    type: 'target',
    title: 'example.com',
    content: 'Primary target domain. Web server running nginx 1.21.0. SSH access available on port 22.',
    timestamp: '2025-07-15T12:02:30Z',
    tags: ['domain', 'web', 'ssh']
  },
  {
    id: 'mem-002',
    type: 'vulnerability',
    title: 'CVE-2021-23017',
    content: 'nginx DNS resolver vulnerability. Allows remote code execution via crafted DNS responses.',
    timestamp: '2025-07-15T12:02:35Z',
    tags: ['cve', 'nginx', 'rce']
  },
  {
    id: 'mem-003',
    type: 'credential',
    title: 'SSH Key Fragment',
    content: 'Partial key material recovered from public repository scan.',
    timestamp: '2025-07-15T11:45:00Z',
    tags: ['ssh', 'credential', 'osint']
  },
  {
    id: 'mem-004',
    type: 'finding',
    title: 'Subdomain Enumeration',
    content: 'Discovered subdomains: api.example.com, staging.example.com, dev.example.com',
    timestamp: '2025-07-15T11:30:00Z',
    tags: ['subdomain', 'recon']
  }
];

export const operationModes = [
  {
    id: 'fast',
    name: 'Fast Scan',
    description: 'Lightweight, uncensored models for rapid reconnaissance and basic targets.',
    accentColor: '#3b82f6'
  },
  {
    id: 'pro',
    name: 'Pro Operator',
    description: 'Thinks longer for more accurate results. Optimized for medium-complexity targets and multi-vector exploits.',
    accentColor: '#a855f7'
  },
  {
    id: 'deep',
    name: 'Deep-Think',
    description: 'Solves complex logic problems and handles modern SPAs. Best for long-term strategic analysis and persistent targets.',
    accentColor: '#ef4444'
  }
];
