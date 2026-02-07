import React, { useState, useRef, useEffect } from 'react';
import { ChevronDown, Zap, Brain, Cpu, Check } from 'lucide-react';
import { cn } from '../lib/utils';

const ModelSelector = ({ selectedModel, onSelectModel }) => {
    const [isOpen, setIsOpen] = useState(false);
    const dropdownRef = useRef(null);

    const models = [
        {
            id: "deepseek/deepseek-r1",
            name: "DeepSeek R1",
            description: "Reasoning & Coding",
            icon: Brain,
            color: "text-emerald-400"
        },
        {
            id: "google/gemini-pro-1.5",
            name: "Gemini 1.5 Pro",
            description: "Balanced Performance",
            icon: Cpu,
            color: "text-blue-400"
        },
        {
            id: "google/gemini-flash-1.5",
            name: "Gemini 1.5 Flash",
            description: "Fast Responses",
            icon: Zap,
            color: "text-yellow-400"
        },
        {
            id: "ollama/llama3",
            name: "Llama 3 (Local)",
            description: "Local Execution",
            icon: Cpu,
            color: "text-purple-400"
        }
    ];

    // Close when clicking outside
    useEffect(() => {
        const handleClickOutside = (event) => {
            if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
                setIsOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const activeModel = models.find(m => m.id === selectedModel) || models[0];

    return (
        <div className="relative" ref={dropdownRef}>
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-zinc-900/50 hover:bg-zinc-800 border border-zinc-800 transition-colors text-xs font-mono text-zinc-400 hover:text-zinc-200"
            >
                <activeModel.icon className={cn("w-3 h-3", activeModel.color)} />
                <span>{activeModel.name}</span>
                <ChevronDown className="w-3 h-3 opacity-50" />
            </button>

            {isOpen && (
                <div className="absolute bottom-full mb-2 right-0 w-64 bg-[#0a0a0a] border border-zinc-800 rounded-xl shadow-2xl overflow-hidden z-50">
                    <div className="px-3 py-2 border-b border-zinc-800">
                        <span className="text-[10px] font-mono font-bold text-zinc-500 uppercase tracking-wider">Model Selection</span>
                    </div>

                    <div className="p-1">
                        {models.map((model) => (
                            <button
                                key={model.id}
                                onClick={() => {
                                    onSelectModel(model.id);
                                    setIsOpen(false);
                                }}
                                className={cn(
                                    "w-full flex items-start gap-3 p-2.5 rounded-lg text-left transition-all group",
                                    selectedModel === model.id ? "bg-zinc-900 border border-zinc-800" : "hover:bg-zinc-900/50 border border-transparent"
                                )}
                            >
                                <div className={cn("mt-0.5 p-1 rounded-full bg-zinc-950 border border-zinc-800", model.color)}>
                                    <model.icon className="w-3 h-3" />
                                </div>

                                <div className="flex-1">
                                    <div className="flex items-center justify-between">
                                        <span className={cn("text-xs font-bold font-mono", selectedModel === model.id ? "text-zinc-100" : "text-zinc-400 group-hover:text-zinc-300")}>
                                            {model.name}
                                        </span>
                                        {selectedModel === model.id && <Check className="w-3 h-3 text-emerald-500" />}
                                    </div>
                                    <p className="text-[10px] text-zinc-600 font-mono mt-0.5">{model.description}</p>
                                </div>
                            </button>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

export default ModelSelector;
