'use client';

import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const dailyAlertsData = [
  { day: 'Mon', alerts: 8 },
  { day: 'Tue', alerts: 4 },
  { day: 'Wed', alerts: 6 },
  { day: 'Thu', alerts: 2 },
  { day: 'Fri', alerts: 7 },
  { day: 'Sat', alerts: 5 },
  { day: 'Sun', alerts: 3 },
  { day: 'Mon', alerts: 9 },
  { day: 'Tue', alerts: 3 },
  { day: 'Wed', alerts: 4 },
];

export function DailyAlertsChart() {
  return (
    <div className="bg-card p-6 rounded-lg shadow-md border">
      <h3 className="font-semibold mb-4 text-lg">Daily Security Alerts</h3>
      <div className="h-96">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={dailyAlertsData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
            <XAxis 
              dataKey="day" 
              axisLine={false}
              tickLine={false}
              className="text-sm text-muted-foreground"
            />
            <YAxis 
              axisLine={false}
              tickLine={false}
              className="text-sm text-muted-foreground"
            />
            <Tooltip
              contentStyle={{
                backgroundColor: 'hsl(var(--card))',
                border: '1px solid hsl(var(--border))',
                borderRadius: '8px',
                boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)',
              }}
            />
            <Bar 
              dataKey="alerts" 
              fill="hsl(var(--primary))"
              radius={[4, 4, 0, 0]}
              className="hover:opacity-80 transition-opacity"
            />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
