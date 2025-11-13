'use client';

import { useEffect } from 'react';
import { useDashboardStore } from '@/lib/stores/dashboard';
import { CardLoading } from '@/components/ui/content-loading';

const stats = [
  {
    title: 'Total Sub-Admins',
    value: 'totalSubAdmins',
    change: '+3 new sub-admins',
    icon: 'supervisor_account',
    gradient: 'from-purple-500 to-indigo-600',
  },
  {
    title: 'Active Geofences',
    value: 'activeGeofences',
    change: '12 new security zones',
    icon: 'public',
    gradient: 'from-blue-500 to-cyan-500',
  },
  {
    title: 'Total Users',
    value: 'activeUsers',
    change: 'All registered users',
    icon: 'people',
    gradient: 'from-green-500 to-teal-500',
  },
  {
    title: 'Security Alerts',
    value: 'totalAlerts',
    change: '8 critical incidents',
    icon: 'warning',
    gradient: 'from-red-500 to-pink-500',
  },
] as const;

export function StatsCards() {
  const { stats: dashboardStats, fetchStats, isLoading } = useDashboardStore();

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  if (isLoading) {
    return <CardLoading count={4} />;
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mb-6">
      {stats.map((stat) => {
        const value = dashboardStats[stat.value as keyof typeof dashboardStats];
        return (
          <div
            key={stat.title}
            className={`bg-gradient-to-br ${stat.gradient} p-4 rounded-lg shadow-lg text-white`}
          >
            <div className="flex justify-between items-start">
              <h3 className="font-semibold">{stat.title}</h3>
              <span className="material-icons-outlined bg-white/20 p-2 rounded-lg">
                {stat.icon}
              </span>
            </div>
            <div className="flex items-baseline mt-2">
              <p className="text-2xl font-bold">
                {typeof value === 'number' ? value.toLocaleString() : String(value || 0)}
              </p>
              {('showIndicator' in stat && stat.showIndicator) ? (
                <div className="w-3 h-3 bg-green-300 rounded-full ml-2 animate-pulse" />
              ) : null}
            </div>
            <p className="text-xs opacity-80 mt-1">{stat.change}</p>
          </div>
        );
      })}
    </div>
  );
}
