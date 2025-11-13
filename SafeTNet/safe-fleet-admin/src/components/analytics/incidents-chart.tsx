'use client';

import { useState, useEffect } from 'react';
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { incidentsService, Incident } from '@/lib/services/incidents';
import { toast } from 'sonner';

export function IncidentsChart() {
  const [chartType, setChartType] = useState<'bar' | 'line'>('bar');
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchIncidents();
  }, []);

  const fetchIncidents = async () => {
    try {
      setLoading(true);
      const data = await incidentsService.getAll();
      setIncidents(data);
    } catch (error) {
      console.error('Error fetching incidents:', error);
      toast.error('Failed to fetch incident trends');
    } finally {
      setLoading(false);
    }
  };

  // Process incidents data into monthly trends
  const processIncidentTrends = () => {
    if (incidents.length === 0) return [];

    const monthlyData: { [key: string]: { resolved: number; unresolved: number } } = {};
    
    incidents.forEach(incident => {
      if (incident.created_at) {
        const date = new Date(incident.created_at);
        const monthKey = date.toLocaleDateString('en-US', { month: 'short', year: '2-digit' });
        
        if (!monthlyData[monthKey]) {
          monthlyData[monthKey] = { resolved: 0, unresolved: 0 };
        }
        
        if (incident.is_resolved) {
          monthlyData[monthKey].resolved++;
        } else {
          monthlyData[monthKey].unresolved++;
        }
      }
    });

    return Object.entries(monthlyData)
      .map(([month, data]) => ({
        month,
        resolved: data.resolved,
        unresolved: data.unresolved,
        total: data.resolved + data.unresolved,
      }))
      .sort((a, b) => {
        const dateA = new Date(a.month);
        const dateB = new Date(b.month);
        return dateA.getTime() - dateB.getTime();
      })
      .slice(-6); // Last 6 months
  };

  const data = processIncidentTrends();

  if (loading) {
    return (
      <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
        <div className="mb-6">
          <h3 className="font-semibold text-lg">Incident Trends</h3>
          <p className="text-xs text-muted-foreground mt-1">Loading incident data...</p>
        </div>
        <div className="h-[400px] flex items-center justify-center">
          <div className="animate-pulse text-muted-foreground">Loading chart...</div>
        </div>
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
        <div className="mb-6">
          <h3 className="font-semibold text-lg">Incident Trends</h3>
          <p className="text-xs text-muted-foreground mt-1">Monthly incident resolution tracking</p>
        </div>
        <div className="h-[400px] flex flex-col items-center justify-center text-muted-foreground">
          <span className="material-icons text-6xl mb-4">security</span>
          <p>No incident data available</p>
          <p className="text-xs mt-2">Incident trends will appear here once data is available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="font-semibold text-lg">Incident Trends</h3>
          <p className="text-xs text-muted-foreground mt-1">Monthly resolution tracking</p>
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={() => setChartType('bar')}
            className={`px-3 py-1 text-xs rounded-lg transition-colors ${
              chartType === 'bar'
                ? 'bg-indigo-100 dark:bg-indigo-900/20 text-indigo-900 dark:text-indigo-100'
                : 'text-muted-foreground hover:bg-muted'
            }`}
          >
            Bar
          </button>
          <button 
            onClick={() => setChartType('line')}
            className={`px-3 py-1 text-xs rounded-lg transition-colors ${
              chartType === 'line'
                ? 'bg-indigo-100 dark:bg-indigo-900/20 text-indigo-900 dark:text-indigo-100'
                : 'text-muted-foreground hover:bg-muted'
            }`}
          >
            Line
          </button>
        </div>
      </div>
      
      <div className="h-[400px]">
        <ResponsiveContainer width="100%" height="100%">
          {chartType === 'bar' ? (
            <BarChart data={data}>
              <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
              <XAxis 
                dataKey="month" 
                tick={{ fontSize: 12 }}
                stroke="hsl(var(--muted-foreground))"
              />
              <YAxis 
                tick={{ fontSize: 12 }}
                stroke="hsl(var(--muted-foreground))"
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'hsl(var(--card))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '8px',
                }}
              />
              <Legend 
                wrapperStyle={{ fontSize: '12px' }}
              />
              <Bar dataKey="resolved" fill="#10b981" radius={[8, 8, 0, 0]} name="Resolved" />
              <Bar dataKey="unresolved" fill="#ef4444" radius={[8, 8, 0, 0]} name="Unresolved" />
            </BarChart>
          ) : (
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
              <XAxis 
                dataKey="month" 
                tick={{ fontSize: 12 }}
                stroke="hsl(var(--muted-foreground))"
              />
              <YAxis 
                tick={{ fontSize: 12 }}
                stroke="hsl(var(--muted-foreground))"
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'hsl(var(--card))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '8px',
                }}
              />
              <Legend 
                wrapperStyle={{ fontSize: '12px' }}
              />
              <Line 
                type="monotone" 
                dataKey="resolved" 
                stroke="#10b981" 
                strokeWidth={3}
                dot={{ fill: '#10b981', r: 4 }}
                name="Resolved"
              />
              <Line 
                type="monotone" 
                dataKey="unresolved" 
                stroke="#ef4444" 
                strokeWidth={3}
                dot={{ fill: '#ef4444', r: 4 }}
                name="Unresolved"
              />
            </LineChart>
          )}
        </ResponsiveContainer>
      </div>
    </div>
  );
}

