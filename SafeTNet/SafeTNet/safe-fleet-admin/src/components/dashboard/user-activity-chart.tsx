'use client';

import { XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart } from 'recharts';

const userActivityData = [
  { time: '00:00', active: 45, total: 1247 },
  { time: '04:00', active: 38, total: 1247 },
  { time: '08:00', active: 267, total: 1247 },
  { time: '12:00', active: 389, total: 1247 },
  { time: '16:00', active: 376, total: 1247 },
  { time: '20:00', active: 254, total: 1247 },
  { time: '24:00', active: 142, total: 1247 },
];

export function UserActivityChart() {
  return (
    <div className="bg-card p-6 rounded-lg shadow-md border">
      <h3 className="font-semibold mb-4 text-lg">User Activity (24h)</h3>
      <div className="h-96">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={userActivityData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
            <defs>
              <linearGradient id="colorActive" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0.1}/>
              </linearGradient>
              <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(var(--chart-2))" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="hsl(var(--chart-2))" stopOpacity={0.1}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
            <XAxis 
              dataKey="time" 
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
              formatter={(value, name) => [
                value,
                name === 'active' ? 'Active Users' : 'Total Users'
              ]}
            />
            <Area
              type="monotone"
              dataKey="total"
              stroke="hsl(var(--chart-2))"
              fillOpacity={1}
              fill="url(#colorTotal)"
              strokeWidth={2}
            />
            <Area
              type="monotone"
              dataKey="active"
              stroke="hsl(var(--primary))"
              fillOpacity={1}
              fill="url(#colorActive)"
              strokeWidth={2}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="flex justify-center space-x-6 mt-4">
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 rounded-full bg-primary"></div>
          <span className="text-sm text-muted-foreground">Active Users</span>
        </div>
        <div className="flex items-center space-x-2">
          <div className="w-3 h-3 rounded-full bg-chart-2"></div>
          <span className="text-sm text-muted-foreground">Total Users</span>
        </div>
      </div>
    </div>
  );
}
