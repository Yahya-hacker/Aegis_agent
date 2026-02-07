import React, { useState } from 'react';
import { Search, Filter, Database, Target, AlertTriangle, Key, FileText, Tag, Trash2, ChevronRight } from 'lucide-react';
import { cn } from '../lib/utils';
import { mockMemoryEntries } from '../data/mock';
import { Card, CardContent } from './ui/card';
import { ScrollArea } from './ui/scroll-area';
import { Input } from './ui/input';

const MemoryView = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState('all');
  const [selectedEntry, setSelectedEntry] = useState(null);

  const typeIcons = {
    target: Target,
    vulnerability: AlertTriangle,
    credential: Key,
    finding: FileText
  };

  const typeColors = {
    target: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
    vulnerability: 'text-red-400 bg-red-500/10 border-red-500/30',
    credential: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    finding: 'text-purple-400 bg-purple-500/10 border-purple-500/30'
  };

  const filterTypes = [
    { id: 'all', label: 'All' },
    { id: 'target', label: 'Targets' },
    { id: 'vulnerability', label: 'Vulnerabilities' },
    { id: 'credential', label: 'Credentials' },
    { id: 'finding', label: 'Findings' }
  ];

  const filteredEntries = mockMemoryEntries.filter(entry => {
    const matchesSearch = entry.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         entry.content.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         entry.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesType = selectedType === 'all' || entry.type === selectedType;
    return matchesSearch && matchesType;
  });

  return (
    <div className="flex flex-col md:flex-row h-full">
      {/* Left Panel - Entry List */}
      <div className={cn(
        'w-full md:w-96 border-b md:border-b-0 md:border-r border-zinc-800 flex flex-col',
        selectedEntry ? 'hidden md:flex' : 'flex'
      )}>
        {/* Header */}
        <div className="p-4 border-b border-zinc-800">
          <div className="flex items-center gap-3 mb-4">
            <Database className="w-6 h-6 text-purple-500" />
            <div>
              <h1 className="text-lg font-mono font-bold text-zinc-100">Cortex Memory</h1>
              <p className="text-zinc-500 font-mono text-xs">Agent Knowledge Base</p>
            </div>
          </div>

          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
            <Input
              type="text"
              placeholder="Search memory..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 bg-[#0a0a0a] border-zinc-800 text-zinc-100 font-mono text-sm placeholder:text-zinc-600"
            />
          </div>
        </div>

        {/* Filter Tabs */}
        <div className="flex gap-1 p-2 border-b border-zinc-800 overflow-x-auto">
          {filterTypes.map((type) => (
            <button
              key={type.id}
              onClick={() => setSelectedType(type.id)}
              className={cn(
                'px-3 py-1.5 rounded-md font-mono text-xs transition-all duration-200 whitespace-nowrap',
                selectedType === type.id
                  ? 'bg-zinc-800 text-zinc-100'
                  : 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/50'
              )}
            >
              {type.label}
            </button>
          ))}
        </div>

        {/* Entry List */}
        <ScrollArea className="flex-1">
          <div className="p-2 space-y-2">
            {filteredEntries.map((entry) => {
              const Icon = typeIcons[entry.type];
              const isSelected = selectedEntry?.id === entry.id;
              
              return (
                <button
                  key={entry.id}
                  onClick={() => setSelectedEntry(entry)}
                  className={cn(
                    'w-full p-3 rounded-lg border transition-all duration-200 text-left',
                    isSelected
                      ? 'bg-zinc-800/50 border-zinc-700'
                      : 'bg-[#0a0a0a] border-zinc-800 hover:bg-zinc-800/30'
                  )}
                >
                  <div className="flex items-start gap-3">
                    <div className={cn('p-2 rounded-lg border', typeColors[entry.type])}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <h3 className="text-zinc-100 font-mono text-sm font-medium truncate">
                        {entry.title}
                      </h3>
                      <p className="text-zinc-500 font-mono text-xs mt-1 line-clamp-2">
                        {entry.content}
                      </p>
                      <div className="flex items-center gap-2 mt-2">
                        {entry.tags.slice(0, 3).map((tag) => (
                          <span 
                            key={tag}
                            className="px-2 py-0.5 bg-zinc-800 rounded text-zinc-400 font-mono text-xs"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                    <ChevronRight className="w-4 h-4 text-zinc-600" />
                  </div>
                </button>
              );
            })}

            {filteredEntries.length === 0 && (
              <div className="text-center py-12">
                <Database className="w-12 h-12 text-zinc-700 mx-auto mb-4" />
                <p className="text-zinc-500 font-mono text-sm">No memory entries found</p>
              </div>
            )}
          </div>
        </ScrollArea>
      </div>

      {/* Right Panel - Entry Detail */}
      <div className={cn(
        'flex-1 flex flex-col',
        selectedEntry ? 'flex' : 'hidden md:flex'
      )}>
        {selectedEntry ? (
          <MemoryDetail 
            entry={selectedEntry} 
            typeIcons={typeIcons} 
            typeColors={typeColors}
            onBack={() => setSelectedEntry(null)}
          />
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <Database className="w-16 h-16 text-zinc-700 mx-auto mb-4" strokeWidth={1} />
              <p className="text-zinc-500 font-mono text-sm">Select a memory entry to view details</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const MemoryDetail = ({ entry, typeIcons, typeColors, onBack }) => {
  const Icon = typeIcons[entry.type];

  return (
    <div className="flex-1 p-4 md:p-6">
      {/* Back button for mobile */}
      <button 
        onClick={onBack}
        className="md:hidden flex items-center gap-2 text-zinc-400 hover:text-zinc-200 font-mono text-sm mb-4 transition-colors"
      >
        <ChevronRight className="w-4 h-4 rotate-180" />
        Back to list
      </button>
      
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-start gap-4">
          <div className={cn('p-3 rounded-lg border', typeColors[entry.type])}>
            <Icon className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-2xl font-mono font-bold text-zinc-100">{entry.title}</h2>
            <p className="text-zinc-500 font-mono text-sm mt-1">
              {new Date(entry.timestamp).toLocaleString()}
            </p>
          </div>
        </div>
        <button className="p-2 rounded-lg hover:bg-zinc-800 transition-colors text-zinc-500 hover:text-red-400">
          <Trash2 className="w-5 h-5" />
        </button>
      </div>

      {/* Content */}
      <Card className="bg-[#0a0a0a] border-zinc-800 mb-6">
        <CardContent className="p-4">
          <h3 className="text-zinc-400 font-mono text-xs uppercase tracking-wider mb-3">Content</h3>
          <p className="text-zinc-100 font-mono text-sm leading-relaxed">{entry.content}</p>
        </CardContent>
      </Card>

      {/* Tags */}
      <Card className="bg-[#0a0a0a] border-zinc-800">
        <CardContent className="p-4">
          <h3 className="text-zinc-400 font-mono text-xs uppercase tracking-wider mb-3 flex items-center gap-2">
            <Tag className="w-4 h-4" />
            Tags
          </h3>
          <div className="flex flex-wrap gap-2">
            {entry.tags.map((tag) => (
              <span 
                key={tag}
                className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 rounded-lg text-zinc-300 font-mono text-sm cursor-pointer transition-colors"
              >
                {tag}
              </span>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default MemoryView;
