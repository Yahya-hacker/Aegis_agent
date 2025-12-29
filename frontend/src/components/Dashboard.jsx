import React from 'react';
import { Ghost, Activity, Cpu, Wrench } from 'lucide-react';
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { mockMissions, mockTelemetryData, mockToolDistribution, mockResourceStats } from '../data/mock';

const Dashboard = () => {
  const hasMissions = mockMissions.length > 0;

  if (!hasMissions) {
    return (
      <div className="flex flex-col items-center justify-center h-full">
        <Ghost className="w-24 h-24 text-zinc-700 mb-6" strokeWidth={1} />
        <h2 className="text-2xl font-mono text-zinc-400 mb-2">Oops, nothing to show here. Nexus is dormant.</h2>
        <p className="text-zinc-600 font-mono text-sm">Start some missions so you can view the agent&apos;s performance metrics.</p>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono font-bold text-zinc-100">Command Overview</h1>
          <p className="text-zinc-500 font-mono text-sm mt-1">Real-time operational intelligence</p>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-emerald-400 font-mono text-sm">SYSTEMS ONLINE</span>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard 
          icon={Activity}
          label="Active Missions"
          value={mockResourceStats.activeMissions}
          accent="blue"
        />
        <StatCard 
          icon={Activity}
          label="Completed"
          value={mockResourceStats.completedMissions}
          accent="purple"
        />
        <StatCard 
          icon={Cpu}
          label="Total Tokens"
          value={mockResourceStats.totalTokens.toLocaleString()}
          accent="blue"
        />
        <StatCard 
          icon={Wrench}
          label="Compute Time"
          value={`${mockResourceStats.totalComputeTime}s`}
          accent="purple"
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Mission Telemetry */}
        <Card className="bg-[#0a0a0a] border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-zinc-100 font-mono text-lg flex items-center gap-2">
              <Activity className="w-5 h-5 text-blue-500" />
              Mission Telemetry
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={mockTelemetryData}>
                  <defs>
                    <linearGradient id="responseGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="toolGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#a855f7" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#a855f7" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                  <XAxis dataKey="time" stroke="#71717a" fontSize={12} fontFamily="JetBrains Mono" />
                  <YAxis stroke="#71717a" fontSize={12} fontFamily="JetBrains Mono" />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#0a0a0a', 
                      border: '1px solid #27272a',
                      borderRadius: '8px',
                      fontFamily: 'JetBrains Mono'
                    }}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="responseTime" 
                    stroke="#3b82f6" 
                    fillOpacity={1} 
                    fill="url(#responseGradient)" 
                    name="Response Time (ms)"
                  />
                  <Area 
                    type="monotone" 
                    dataKey="toolExecution" 
                    stroke="#a855f7" 
                    fillOpacity={1} 
                    fill="url(#toolGradient)" 
                    name="Tool Execution (ms)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>

        {/* Tool Distribution */}
        <Card className="bg-[#0a0a0a] border-zinc-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-zinc-100 font-mono text-lg flex items-center gap-2">
              <Wrench className="w-5 h-5 text-purple-500" />
              Tool Distribution
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={mockToolDistribution} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#27272a" horizontal={false} />
                  <XAxis type="number" stroke="#71717a" fontSize={12} fontFamily="JetBrains Mono" />
                  <YAxis 
                    type="category" 
                    dataKey="name" 
                    stroke="#71717a" 
                    fontSize={12} 
                    fontFamily="JetBrains Mono"
                    width={80}
                  />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#0a0a0a', 
                      border: '1px solid #27272a',
                      borderRadius: '8px',
                      fontFamily: 'JetBrains Mono'
                    }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

const StatCard = ({ icon: Icon, label, value, accent }) => {
  const accentColors = {
    blue: 'text-blue-500 bg-blue-500/10 border-blue-500/30',
    purple: 'text-purple-500 bg-purple-500/10 border-purple-500/30'
  };

  return (
    <Card className="bg-[#0a0a0a] border-zinc-800">
      <CardContent className="p-4">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg border ${accentColors[accent]}`}>
            <Icon className="w-5 h-5" />
          </div>
          <div>
            <p className="text-zinc-500 font-mono text-xs uppercase tracking-wider">{label}</p>
            <p className="text-zinc-100 font-mono text-xl font-bold">{value}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default Dashboard;
