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
import { alertsService, Alert } from '@/lib/services/alerts';
import { toast } from 'sonner';

export function AlertTrendsChart() {
  const [chartType, setChartType] = useState<'bar' | 'line'>('bar');
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAlerts();
  }, []);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const data = await alertsService.getAll();
      setAlerts(data);
    } catch (error) {
      console.error('Error fetching alerts:', error);
      toast.error('Failed to fetch alert trends');
    } finally {
      setLoading(false);
    }
  };

  // Get all unique alert types from the data
  const getAllAlertTypes = () => {
    const types = new Set<string>();
    alerts.forEach(alert => {
      if (alert.alert_type) {
        types.add(alert.alert_type);
      }
    });
    return Array.from(types);
  };

  // Color mapping for alert types
  const getColorForType = (type: string): string => {
    const colorMap: { [key: string]: string } = {
      'GEOFENCE_ENTER': '#10b981',
      'GEOFENCE_EXIT': '#3b82f6',
      'GEOFENCE_VIOLATION': '#ef4444',
      'SYSTEM_ERROR': '#f59e0b',
      'SECURITY_BREACH': '#dc2626',
      'MAINTENANCE': '#8b5cf6',
    };
    return colorMap[type] || '#6b7280';
  };

  // Process alerts data into weekly trends
  const processAlertTrends = () => {
    if (alerts.length === 0) return [];

    // Group alerts by week
    const weeklyData: { [key: string]: { [key: string]: number } } = {};
    
    alerts.forEach(alert => {
      const date = new Date(alert.created_at);
      const weekStart = new Date(date);
      weekStart.setDate(date.getDate() - date.getDay()); // Start of week (Sunday)
      const weekKey = weekStart.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      
      if (!weeklyData[weekKey]) {
        weeklyData[weekKey] = {};
      }
      
      const alertType = alert.alert_type || 'System';
      weeklyData[weekKey][alertType] = (weeklyData[weekKey][alertType] || 0) + 1;
    });

    // Convert to array format for recharts
    return Object.entries(weeklyData)
      .map(([date, types]) => ({
        date,
        ...types,
      }))
      .slice(-7); // Last 7 weeks
  };

  const data = processAlertTrends();
  const alertTypes = getAllAlertTypes();

  if (loading) {
    return (
      <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
        <div className="mb-6">
          <h3 className="font-semibold text-lg">Alert Trends</h3>
          <p className="text-xs text-muted-foreground mt-1">Loading alert data...</p>
        </div>
        <div className="h-[435px] flex items-center justify-center">
          <div className="animate-pulse text-muted-foreground">Loading chart...</div>
        </div>
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
        <div className="mb-6">
          <h3 className="font-semibold text-lg">Alert Trends</h3>
          <p className="text-xs text-muted-foreground mt-1">Weekly alert distribution over time</p>
        </div>
        <div className="h-[435px] flex flex-col items-center justify-center text-muted-foreground">
          <span className="material-icons text-6xl mb-4">show_chart</span>
          <p>No alert data available</p>
          <p className="text-xs mt-2">Alert trends will appear here once data is available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="font-semibold text-lg">Alert Trends</h3>
          <p className="text-xs text-muted-foreground mt-1">Weekly alert distribution from API data</p>
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
      
      <div className="h-[435px]">
        <ResponsiveContainer width="100%" height="100%">
          {chartType === 'bar' ? (
            <BarChart data={data}>
              <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
              <XAxis 
                dataKey="date" 
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
              {alertTypes.map((type) => (
                <Bar 
                  key={type} 
                  dataKey={type} 
                  fill={getColorForType(type)} 
                  radius={[8, 8, 0, 0]} 
                />
              ))}
            </BarChart>
          ) : (
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
              <XAxis 
                dataKey="date" 
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
              {alertTypes.map((type) => (
                <Line 
                  key={type}
                  type="monotone" 
                  dataKey={type} 
                  stroke={getColorForType(type)} 
                  strokeWidth={3}
                  dot={{ fill: getColorForType(type), r: 4 }}
                />
              ))}
            </LineChart>
          )}
        </ResponsiveContainer>
      </div>
    </div>
  );
}

