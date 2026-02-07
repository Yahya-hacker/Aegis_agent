import React, { useState } from 'react';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/600.css';
import '@fontsource/jetbrains-mono/700.css';
import '@fontsource/inter/400.css';
import '@fontsource/inter/500.css';
import '@fontsource/inter/600.css';
import './App.css';
import Sidebar from './components/Sidebar';
import Dashboard from './components/Dashboard';
import ChatView from './components/ChatView';
import MemoryView from './components/MemoryView';

function App() {
  const [activeView, setActiveView] = useState('mission');

  const renderView = () => {
    switch (activeView) {
      case 'overview':
        return <Dashboard />;
      case 'mission':
        return <ChatView />;
      case 'memory':
        return <MemoryView />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="min-h-screen bg-[#050505] text-zinc-100">
      <Sidebar activeView={activeView} setActiveView={setActiveView} />
      <main className="ml-16 h-screen overflow-hidden">
        {renderView()}
      </main>
    </div>
  );
}

export default App;
