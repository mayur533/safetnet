'use client';

import { useEffect, useState } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { usersService } from '@/lib/services/users';
import { toast } from 'sonner';

export function UserActivityChart() {
  const [users, setUsers] = useState<unknown[]>([]);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<'weekly' | 'monthly' | 'all'>('weekly');
  const [selectedWeek, setSelectedWeek] = useState(0); // 0 = current week, -1 = last week, etc.
  const [selectedMonth, setSelectedMonth] = useState(0); // 0 = current month, -1 = last month, etc.

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
      toast.error('Failed to fetch user activity');
    } finally {
      setLoading(false);
    }
  };

  // Process users data based on view mode
  const processUserActivity = () => {
    if (users.length === 0) return [];

    if (viewMode === 'weekly') {
      // Filter users for selected week
      const now = new Date();
      const weekStart = new Date(now);
      weekStart.setDate(now.getDate() - now.getDay() + (selectedWeek * 7)); // Start of selected week
      weekStart.setHours(0, 0, 0, 0);
      const weekEnd = new Date(weekStart);
      weekEnd.setDate(weekStart.getDate() + 6);
      weekEnd.setHours(23, 59, 59, 999);

      const weeklyData: { [key: string]: number } = {
        'Sun': 0, 'Mon': 0, 'Tue': 0, 'Wed': 0, 'Thu': 0, 'Fri': 0, 'Sat': 0,
      };

      const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
      
      (users as { date_joined?: string }[]).forEach((user) => {
        if (user.date_joined) {
          const date = new Date(user.date_joined);
          if (date >= weekStart && date <= weekEnd) {
            const dayName = dayNames[date.getDay()];
            weeklyData[dayName] = (weeklyData[dayName] || 0) + 1;
          }
        }
      });

      return dayNames.map(day => ({
        label: day,
        users: weeklyData[day],
      }));
    } else if (viewMode === 'monthly') {
      // Filter users for selected month and group by day
      const now = new Date();
      const targetDate = new Date(now.getFullYear(), now.getMonth() + selectedMonth, 1);
      const monthStart = new Date(targetDate.getFullYear(), targetDate.getMonth(), 1);
      const monthEnd = new Date(targetDate.getFullYear(), targetDate.getMonth() + 1, 0);

      const dailyData: { [key: string]: number } = {};
      const daysInMonth = monthEnd.getDate();

      for (let i = 1; i <= daysInMonth; i++) {
        dailyData[i.toString()] = 0;
      }

      (users as { date_joined?: string }[]).forEach(user => {
        if (user.date_joined) {
          const date = new Date(user.date_joined);
          if (date >= monthStart && date <= monthEnd) {
            const day = date.getDate().toString();
            dailyData[day] = (dailyData[day] || 0) + 1;
          }
        }
      });

      return Object.entries(dailyData).map(([day, count]) => ({
        label: day,
        users: count,
      }));
    } else {
      // All-time: Group by month
      const monthlyData: { [key: string]: number } = {};

      (users as { date_joined?: string }[]).forEach(user => {
        if (user.date_joined) {
          const date = new Date(user.date_joined);
          const monthKey = date.toLocaleDateString('en-US', { month: 'short', year: '2-digit' });
          monthlyData[monthKey] = (monthlyData[monthKey] || 0) + 1;
        }
      });

      return Object.entries(monthlyData)
        .sort((a, b) => {
          const dateA = new Date(a[0]);
          const dateB = new Date(b[0]);
          return dateA.getTime() - dateB.getTime();
        })
        .map(([month, count]) => ({
          label: month,
          users: count,
        }));
    }
  };

  const data = processUserActivity();

  const getChartTitle = () => {
    if (viewMode === 'weekly') {
      if (selectedWeek === 0) return 'This Week';
      if (selectedWeek === -1) return 'Last Week';
      return `${Math.abs(selectedWeek)} Weeks Ago`;
    } else if (viewMode === 'monthly') {
      const now = new Date();
      const targetDate = new Date(now.getFullYear(), now.getMonth() + selectedMonth, 1);
      return targetDate.toLocaleDateString('en-US', { month: 'long', year: 'numeric' });
    }
    return 'All Time';
  };

  if (loading) {
    return (
      <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
        <div className="mb-6">
          <h3 className="font-semibold text-lg">User Registrations</h3>
          <p className="text-xs text-muted-foreground mt-1">Loading...</p>
        </div>
        <div className="h-64 flex items-center justify-center">
          <div className="animate-pulse text-muted-foreground">Loading chart...</div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="font-semibold text-lg">User Registrations - {getChartTitle()}</h3>
          <p className="text-xs text-muted-foreground mt-1">New user signups - Real data from API</p>
        </div>

        <div className="flex items-center gap-3">
          {/* View Mode Toggle */}
          <div className="flex items-center gap-2">
            <button 
              onClick={() => {
                setViewMode('weekly');
                setSelectedWeek(0);
              }}
              className={`px-3 py-1 text-xs rounded-lg transition-colors ${
                viewMode === 'weekly'
                  ? 'bg-indigo-100 dark:bg-indigo-900/20 text-indigo-900 dark:text-indigo-100'
                  : 'text-muted-foreground hover:bg-muted'
              }`}
            >
              Weekly
            </button>
            <button 
              onClick={() => {
                setViewMode('monthly');
                setSelectedMonth(0);
              }}
              className={`px-3 py-1 text-xs rounded-lg transition-colors ${
                viewMode === 'monthly'
                  ? 'bg-indigo-100 dark:bg-indigo-900/20 text-indigo-900 dark:text-indigo-100'
                  : 'text-muted-foreground hover:bg-muted'
              }`}
            >
              Monthly
            </button>
            <button 
              onClick={() => setViewMode('all')}
              className={`px-3 py-1 text-xs rounded-lg transition-colors ${
                viewMode === 'all'
                  ? 'bg-indigo-100 dark:bg-indigo-900/20 text-indigo-900 dark:text-indigo-100'
                  : 'text-muted-foreground hover:bg-muted'
              }`}
            >
              All
            </button>
          </div>

          {/* Week Selector */}
          {viewMode === 'weekly' && (
            <div className="flex items-center gap-2">
              <button
                onClick={() => setSelectedWeek(selectedWeek - 1)}
                className="p-1 hover:bg-muted rounded-lg transition-colors"
                title="Previous Week"
              >
                <span className="material-icons text-sm">chevron_left</span>
              </button>
              <span className="text-xs text-muted-foreground min-w-[80px] text-center">
                {selectedWeek === 0 ? 'Current' : `${Math.abs(selectedWeek)}w ago`}
              </span>
              <button
                onClick={() => setSelectedWeek(selectedWeek + 1)}
                disabled={selectedWeek >= 0}
                className="p-1 hover:bg-muted rounded-lg transition-colors disabled:opacity-50"
                title="Next Week"
              >
                <span className="material-icons text-sm">chevron_right</span>
              </button>
            </div>
          )}

          {/* Month Selector */}
          {viewMode === 'monthly' && (
            <div className="flex items-center gap-2">
              <button
                onClick={() => setSelectedMonth(selectedMonth - 1)}
                className="p-1 hover:bg-muted rounded-lg transition-colors"
                title="Previous Month"
              >
                <span className="material-icons text-sm">chevron_left</span>
              </button>
              <span className="text-xs text-muted-foreground min-w-[100px] text-center">
                {selectedMonth === 0 ? 'Current' : `${Math.abs(selectedMonth)}m ago`}
              </span>
              <button
                onClick={() => setSelectedMonth(selectedMonth + 1)}
                disabled={selectedMonth >= 0}
                className="p-1 hover:bg-muted rounded-lg transition-colors disabled:opacity-50"
                title="Next Month"
              >
                <span className="material-icons text-sm">chevron_right</span>
              </button>
            </div>
          )}
        </div>
      </div>
      
      <div className="h-64">
        {data.length === 0 || data.every(d => d.users === 0) ? (
          <div className="h-full flex flex-col items-center justify-center text-muted-foreground">
            <span className="material-icons text-5xl mb-3">person_add</span>
            <p className="text-sm">No registrations in this period</p>
            <p className="text-xs mt-1">Try selecting a different time range</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data}>
              <defs>
                <linearGradient id="colorUsers" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
              <XAxis 
                dataKey="label" 
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
              <Area
                type="monotone"
                dataKey="users"
                stroke="#6366f1"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorUsers)"
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}




