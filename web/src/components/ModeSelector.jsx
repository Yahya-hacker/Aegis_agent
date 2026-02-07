import React from 'react';
import { Zap, Shield, Brain } from 'lucide-react';
import { cn } from '../lib/utils';
import { operationModes } from '../data/mock';

const ModeSelector = ({ selectedMode, setSelectedMode }) => {
  const modeIcons = {
    fast: Zap,
    pro: Shield,
    deep: Brain
  };

  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 sm:gap-3 mb-4">
      {operationModes.map((mode) => {
        const Icon = modeIcons[mode.id];
        const isSelected = selectedMode === mode.id;
        
        return (
          <button
            key={mode.id}
            onClick={() => setSelectedMode(mode.id)}
            className={cn(
              'p-3 sm:p-4 rounded-lg border transition-all duration-300 text-left',
              'hover:bg-zinc-900/50',
              isSelected 
                ? 'border-opacity-100 bg-zinc-900/30' 
                : 'border-zinc-800 bg-[#0a0a0a]'
            )}
            style={{
              borderColor: isSelected ? mode.accentColor : undefined,
              boxShadow: isSelected ? `0 0 15px ${mode.accentColor}40` : 'none'
            }}
          >
            <div className="flex items-center gap-2 mb-1 sm:mb-2">
              <Icon 
                className="w-4 h-4 flex-shrink-0" 
                style={{ color: mode.accentColor }}
              />
              <span 
                className="font-mono text-xs sm:text-sm font-semibold uppercase tracking-wider"
                style={{ color: isSelected ? mode.accentColor : '#a1a1aa' }}
              >
                {mode.name}
              </span>
            </div>
            <p className="text-zinc-500 font-mono text-[10px] sm:text-xs leading-relaxed hidden sm:block">
              {mode.description}
            </p>
          </button>
        );
      })}
    </div>
  );
};

export default ModeSelector;
