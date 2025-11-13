'use client';

import { useEffect, useState } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import { alertsService, Alert } from '@/lib/services/alerts';
import { toast } from 'sonner';

const COLORS: { [key: string]: string } = {
  'GEOFENCE_ENTER': '#10b981',
  'GEOFENCE_EXIT': '#3b82f6',
  'GEOFENCE_VIOLATION': '#ef4444',
  'SYSTEM_ERROR': '#f59e0b',
  'SECURITY_BREACH': '#dc2626',
  'MAINTENANCE': '#8b5cf6',
  'default': '#6b7280',
};

export function AlertTypesChart() {
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
      toast.error('Failed to fetch alert types');
    } finally {
      setLoading(false);
    }
  };

  // Process alerts data into type distribution
  const processAlertTypes = () => {
    if (alerts.length === 0) return [];

    const typeCounts: { [key: string]: number } = {};
    
    alerts.forEach(alert => {
      const type = alert.alert_type || 'System';
      typeCounts[type] = (typeCounts[type] || 0) + 1;
    });

    return Object.entries(typeCounts).map(([name, value]) => ({
      name,
      value,
      color: COLORS[name] || COLORS['default'],
    }));
  };

  const data = processAlertTypes();

  if (loading) {
    return (
      <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
        <div className="mb-6">
          <h3 className="font-semibold text-lg">Alert Types Distribution</h3>
          <p className="text-xs text-muted-foreground mt-1">Loading...</p>
        </div>
        <div className="h-80 flex items-center justify-center">
          <div className="animate-pulse text-muted-foreground">Loading chart...</div>
        </div>
      </div>
    );
  }

  if (data.length === 0) {
    return (
      <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
        <div className="mb-6">
          <h3 className="font-semibold text-lg">Alert Types Distribution</h3>
          <p className="text-xs text-muted-foreground mt-1">Breakdown by category</p>
        </div>
        <div className="h-80 flex flex-col items-center justify-center text-muted-foreground">
          <span className="material-icons text-6xl mb-4">pie_chart</span>
          <p>No alert data available</p>
          <p className="text-xs mt-2">Distribution will appear here once data is available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
      <div className="mb-6">
        <h3 className="font-semibold text-lg">Alert Types Distribution</h3>
        <p className="text-xs text-muted-foreground mt-1">Real-time data from API</p>
      </div>
      
      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              labelLine={false}
              label={false}
              outerRadius={100}
              fill="#8884d8"
              dataKey="value"
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: 'hsl(var(--card))',
                border: '1px solid hsl(var(--border))',
                borderRadius: '8px',
              }}
            />
            <Legend 
              verticalAlign="bottom"
              height={36}
              wrapperStyle={{ fontSize: '12px' }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>

      {/* Stats */}
      <div className="mt-4 pt-4 border-t border-border/50 grid grid-cols-2 gap-3">
        {data.slice(0, 4).map((item) => (
          <div key={item.name} className="flex items-center gap-2">
            <div
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: item.color }}
            ></div>
            <div className="flex-1">
              <p className="text-xs text-muted-foreground">{item.name}</p>
              <p className="text-sm font-semibold">{item.value}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}




