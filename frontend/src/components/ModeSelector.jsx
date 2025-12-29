import React, { useEffect, useState } from 'react';
import { Zap, Shield, Brain, Check, Loader2 } from 'lucide-react';
import { cn } from '../lib/utils';
import { operationModes } from '../data/mock';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const ModeSelector = ({ selectedMode, setSelectedMode }) => {
  const [isLoading, setIsLoading] = useState(false);
  const [modeDetails, setModeDetails] = useState(null);
  
  const modeIcons = {
    fast: Zap,
    pro: Shield,
    deep: Brain
  };

  // Fetch mode details when selection changes
  useEffect(() => {
    const mode = operationModes.find(m => m.id === selectedMode);
    setModeDetails(mode);
  }, [selectedMode]);

  const handleModeSelect = async (modeId) => {
    if (modeId === selectedMode || isLoading) return;
    
    setIsLoading(true);
    
    try {
      // Call backend to switch mode
      const response = await fetch(`${API_BASE}/api/modes/select/${modeId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      
      if (response.ok) {
        setSelectedMode(modeId);
        console.log(`Mode switched to: ${modeId}`);
      } else {
        console.error('Failed to switch mode');
        // Still update locally even if backend fails
        setSelectedMode(modeId);
      }
    } catch (error) {
      console.error('Error switching mode:', error);
      // Update locally even on network error
      setSelectedMode(modeId);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="space-y-4 mb-4">
      {/* Mode Selection Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 sm:gap-3">
        {operationModes.map((mode) => {
          const Icon = modeIcons[mode.id];
          const isSelected = selectedMode === mode.id;
          
          return (
            <button
              key={mode.id}
              onClick={() => handleModeSelect(mode.id)}
              disabled={isLoading}
              className={cn(
                'p-3 sm:p-4 rounded-lg border transition-all duration-300 text-left relative',
                'hover:bg-zinc-900/50',
                isSelected 
                  ? 'border-opacity-100 bg-zinc-900/30' 
                  : 'border-zinc-800 bg-[#0a0a0a]',
                isLoading && 'opacity-50 cursor-not-allowed'
              )}
              style={{
                borderColor: isSelected ? mode.accentColor : undefined,
                boxShadow: isSelected ? `0 0 15px ${mode.accentColor}40` : 'none'
              }}
            >
              {/* Selection indicator */}
              {isSelected && (
                <div 
                  className="absolute top-2 right-2 w-5 h-5 rounded-full flex items-center justify-center"
                  style={{ backgroundColor: mode.accentColor }}
                >
                  <Check className="w-3 h-3 text-white" />
                </div>
              )}
              
              <div className="flex items-center gap-2 mb-1 sm:mb-2">
                {isLoading && selectedMode !== mode.id ? (
                  <Loader2 
                    className="w-4 h-4 animate-spin" 
                    style={{ color: mode.accentColor }}
                  />
                ) : (
                  <Icon 
                    className="w-4 h-4 flex-shrink-0" 
                    style={{ color: mode.accentColor }}
                  />
                )}
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

      {/* Active Mode Details */}
      {modeDetails && modeDetails.models && (
        <div className="bg-zinc-900/30 border border-zinc-800 rounded-lg p-3">
          <div className="flex items-center gap-2 mb-2">
            <div 
              className="w-2 h-2 rounded-full animate-pulse"
              style={{ backgroundColor: modeDetails.accentColor }}
            />
            <span className="text-zinc-400 font-mono text-xs uppercase tracking-wider">
              Active Models
            </span>
          </div>
          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-zinc-500">Planner:</span>
              <span className="text-zinc-300 truncate ml-2" title={modeDetails.models.planner}>
                {modeDetails.models.planner.split('/').pop()}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-zinc-500">Coder:</span>
              <span className="text-zinc-300 truncate ml-2" title={modeDetails.models.coder}>
                {modeDetails.models.coder.split('/').pop()}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-zinc-500">Vision:</span>
              <span className="text-zinc-300 truncate ml-2" title={modeDetails.models.vision}>
                {modeDetails.models.vision.split('/').pop()}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-zinc-500">Reasoner:</span>
              <span className="text-zinc-300 truncate ml-2" title={modeDetails.models.reasoner}>
                {modeDetails.models.reasoner.split('/').pop()}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ModeSelector;
