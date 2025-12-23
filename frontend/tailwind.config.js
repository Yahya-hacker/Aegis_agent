/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Cyberpunk dark theme
        'cyber-bg': '#0a0a0f',
        'cyber-surface': '#12121a',
        'cyber-card': '#1a1a25',
        'cyber-border': '#2a2a3a',
        'cyber-accent': '#00d9ff',
        'cyber-accent-dim': '#00a8c7',
        'cyber-success': '#00ff88',
        'cyber-warning': '#ffaa00',
        'cyber-error': '#ff4466',
        'cyber-text': '#e0e0e0',
        'cyber-text-dim': '#888899',
        // Swarm colors
        'swarm-red': '#ff4466',
        'swarm-blue': '#4488ff',
        'swarm-judge': '#aa44ff',
      },
      fontFamily: {
        'mono': ['JetBrains Mono', 'Fira Code', 'Consolas', 'monospace'],
        'sans': ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'scan': 'scan 2s ease-in-out infinite',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(0, 217, 255, 0.3)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 217, 255, 0.6)' },
        },
        scan: {
          '0%, 100%': { opacity: 0.3 },
          '50%': { opacity: 1 },
        },
      },
    },
  },
  plugins: [],
}
