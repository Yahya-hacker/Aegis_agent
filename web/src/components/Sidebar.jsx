import React from 'react';
import { LayoutDashboard, Terminal, Database } from 'lucide-react';
import NexusIcon from './NexusIcon';
import { cn } from '../lib/utils';

const Sidebar = ({ activeView, setActiveView }) => {
  const navItems = [
    { id: 'overview', icon: LayoutDashboard, label: 'Overview' },
    { id: 'mission', icon: Terminal, label: 'Mission Control' },
    { id: 'memory', icon: Database, label: 'Cortex Memory' }
  ];

  return (
    <div className="fixed left-0 top-0 h-full w-16 bg-[#050505] border-r border-zinc-800 flex flex-col items-center py-4 z-50">
      {/* Logo */}
      <div className="mb-8 p-2">
        <NexusIcon size={32} />
      </div>

      {/* Navigation */}
      <nav className="flex flex-col gap-2 flex-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeView === item.id;
          
          return (
            <button
              key={item.id}
              onClick={() => setActiveView(item.id)}
              className={cn(
                'w-12 h-12 rounded-lg flex items-center justify-center transition-all duration-200',
                'hover:bg-zinc-800/50',
                isActive && 'bg-zinc-800 border border-zinc-700'
              )}
              title={item.label}
            >
              <Icon 
                size={22} 
                className={cn(
                  'transition-colors duration-200',
                  isActive ? 'text-blue-500' : 'text-zinc-500 hover:text-zinc-300'
                )}
              />
            </button>
          );
        })}
      </nav>

      {/* Status indicator */}
      <div className="mt-auto pb-4">
        <div className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse" title="System Online" />
      </div>
    </div>
  );
};

export default Sidebar;
