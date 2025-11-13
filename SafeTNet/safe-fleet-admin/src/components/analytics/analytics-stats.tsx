'use client';

import { useEffect, useState } from 'react';
import { analyticsService, AnalyticsData } from '@/lib/services/analytics';
import { toast } from 'sonner';

export function AnalyticsStats() {
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAnalytics();
  }, []);

  const fetchAnalytics = async () => {
    try {
      setLoading(true);
      const data = await analyticsService.getAnalytics();
      setAnalytics(data);
    } catch (error) {
      console.error('Error fetching analytics:', error);
      toast.error('Failed to fetch analytics stats');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="bg-gradient-to-br from-gray-400 to-gray-500 p-6 rounded-xl shadow-lg animate-pulse h-32"></div>
        ))}
      </div>
    );
  }

  if (!analytics) {
    return (
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="col-span-4 text-center py-8 text-muted-foreground">
          Failed to load analytics stats
        </div>
      </div>
    );
  }

  const stats = [
    {
      title: 'Total Alerts (30d)',
      value: analytics.alerts_last_30_days.toLocaleString(),
      change: `${analytics.total_alerts} total`,
      trend: 'up',
      icon: 'notifications_active',
      gradient: 'from-indigo-500 to-purple-600',
    },
    {
      title: 'Response Time',
      value: `${analytics.avg_response_time.toFixed(1)} min`,
      change: `${analytics.alerts_today} alerts today`,
      trend: 'down',
      icon: 'timer',
      gradient: 'from-green-500 to-teal-600',
    },
    {
      title: 'Resolution Rate',
      value: `${analytics.resolution_rate.toFixed(1)}%`,
      change: `${analytics.critical_alerts} critical`,
      trend: 'up',
      icon: 'check_circle',
      gradient: 'from-blue-500 to-cyan-600',
    },
    {
      title: 'Active Users',
      value: analytics.active_users.toLocaleString(),
      change: `${analytics.total_users} total users`,
      trend: 'up',
      icon: 'people',
      gradient: 'from-orange-500 to-red-600',
    },
  ];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
      {stats.map((stat) => (
        <div
          key={stat.title}
          className={`bg-gradient-to-br ${stat.gradient} p-6 rounded-xl shadow-lg text-white relative overflow-hidden group`}
        >
          {/* Background glow */}
          <div className="absolute top-0 right-0 w-32 h-32 bg-white/10 rounded-full blur-3xl group-hover:w-40 group-hover:h-40 transition-all duration-300"></div>
          
          <div className="relative z-10">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <p className="text-sm opacity-90 font-medium">{stat.title}</p>
                <div className="flex items-baseline gap-3 mt-2">
                  <h3 className="text-3xl font-bold">{stat.value}</h3>
                </div>
                <div className="flex items-center gap-2 mt-2">
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full ${
                      stat.trend === 'up'
                        ? 'bg-white/20 text-white'
                        : 'bg-white/20 text-white'
                    }`}
                  >
                    {stat.trend === 'up' ? '↑' : '↓'} {stat.change}
                  </span>
                </div>
              </div>
              <div className="ml-4">
                <span
                  className="material-icons-outlined"
                  style={{ fontSize: '48px', opacity: 0.7 }}
                >
                  {stat.icon}
                </span>
              </div>
            </div>
          </div>

          {/* Bottom accent */}
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-white/30"></div>
        </div>
      ))}
    </div>
  );
}




