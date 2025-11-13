'use client';

import { useEffect, useState } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';
import { usersService } from '@/lib/services/users';
import { toast } from 'sonner';

const COLORS: { [key: string]: string } = {
  'SUPER_ADMIN': '#ef4444',
  'SUB_ADMIN': '#f59e0b',
  'USER': '#3b82f6',
  'OFFICER': '#10b981',
  'default': '#6b7280',
};

export function UserRolesChart() {
  const [users, setUsers] = useState<unknown[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const data = await usersService.getAll();
      setUsers(data);
    } catch (error) {
      console.error('Error fetching users:', error);
      toast.error('Failed to fetch user roles');
    } finally {
      setLoading(false);
    }
  };

  // Process users data into role distribution
  const processUserRoles = () => {
    if (users.length === 0) return [];

    const roleCounts: { [key: string]: number } = {};
    
    (users as { role?: string }[]).forEach(user => {
      const role = user.role || 'USER';
      roleCounts[role] = (roleCounts[role] || 0) + 1;
    });

    return Object.entries(roleCounts).map(([name, value]) => ({
      name,
      value,
      color: COLORS[name] || COLORS['default'],
    }));
  };

  const data = processUserRoles();

  if (loading) {
    return (
      <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
        <div className="mb-6">
          <h3 className="font-semibold text-lg">User Roles Distribution</h3>
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
          <h3 className="font-semibold text-lg">User Roles Distribution</h3>
          <p className="text-xs text-muted-foreground mt-1">Breakdown by role</p>
        </div>
        <div className="h-80 flex flex-col items-center justify-center text-muted-foreground">
          <span className="material-icons text-6xl mb-4">group</span>
          <p>No user data available</p>
          <p className="text-xs mt-2">Distribution will appear here once data is available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
      <div className="mb-6">
        <h3 className="font-semibold text-lg">User Roles Distribution</h3>
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

