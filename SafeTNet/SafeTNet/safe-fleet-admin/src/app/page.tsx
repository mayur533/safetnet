'use client';

import { useState, useEffect } from 'react';
import { StatsCards } from '@/components/dashboard/stats-cards';
import { GeofencesMap } from '@/components/dashboard/geofences-map';
import { DailyAlertsChart } from '@/components/dashboard/daily-alerts-chart';
import { UserActivityChart } from '@/components/dashboard/user-activity-chart';
import { RecentAlertsTable } from '@/components/dashboard/recent-alerts-table';
import { CardLoading, ContentLoading } from '@/components/ui/content-loading';
import { useDashboardStore } from '@/lib/stores/dashboard';

export default function DashboardPage() {
  const [pageLoading, setPageLoading] = useState(true);
  const { fetchAlerts } = useDashboardStore();

  useEffect(() => {
    // Initial page load
    const timer = setTimeout(() => {
      setPageLoading(false);
    }, 1000);
    
    // Fetch alerts on mount
    fetchAlerts();
    
    return () => clearTimeout(timer);
  }, [fetchAlerts]);

  if (pageLoading) {
    return (
      <div className="space-y-6">
        {/* Stats Cards Loading */}
        <CardLoading count={4} />

        {/* Main content grid */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Map Loading */}
          <div className="lg:col-span-2 bg-card rounded-lg shadow-md border overflow-hidden" style={{ height: '500px' }}>
            <ContentLoading text="Loading map..." />
          </div>

          {/* Security Overview Loading */}
          <div className="bg-card p-6 rounded-lg shadow-md border">
            <div className="h-5 w-32 bg-muted rounded mb-4 animate-pulse"></div>
            <div className="space-y-3">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="flex items-center justify-between animate-pulse" style={{ animationDelay: `${i * 50}ms` }}>
                  <div className="h-3 w-32 bg-muted/60 rounded"></div>
                  <div className="h-4 w-12 bg-muted rounded"></div>
                </div>
              ))}
            </div>
          </div>

          {/* Recent Activity Loading */}
          <div className="bg-card p-6 rounded-lg shadow-md border">
            <div className="h-5 w-32 bg-muted rounded mb-4 animate-pulse"></div>
            <div className="space-y-3">
              {Array.from({ length: 8 }).map((_, i) => (
                <div key={i} className="flex items-start space-x-3 animate-pulse" style={{ animationDelay: `${i * 50}ms` }}>
                  <div className="w-2 h-2 bg-muted rounded-full mt-2"></div>
                  <div className="flex-1 space-y-1">
                    <div className="h-3 w-full bg-muted/60 rounded"></div>
                    <div className="h-2 w-20 bg-muted/40 rounded"></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Charts Loading */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-card p-6 rounded-lg shadow-md border">
            <div className="h-5 w-32 bg-muted rounded mb-4 animate-pulse"></div>
            <div className="h-64 bg-muted/40 rounded animate-pulse"></div>
          </div>
          <div className="bg-card p-6 rounded-lg shadow-md border">
            <div className="h-5 w-32 bg-muted rounded mb-4 animate-pulse"></div>
            <div className="h-64 bg-muted/40 rounded animate-pulse"></div>
          </div>
        </div>

        {/* Recent Alerts Table Loading */}
        <div className="bg-card p-6 rounded-lg shadow-md border">
          <div className="h-5 w-32 bg-muted rounded mb-4 animate-pulse"></div>
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex space-x-4 animate-pulse" style={{ animationDelay: `${i * 50}ms` }}>
                <div className="h-4 flex-1 bg-muted/60 rounded"></div>
                <div className="h-4 flex-1 bg-muted/60 rounded"></div>
                <div className="h-4 flex-1 bg-muted/60 rounded"></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="space-y-6 pb-0">
        <StatsCards />
      
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-2" style={{ height: '500px' }}>
          <GeofencesMap />
        </div>
        <div className="bg-card p-6 rounded-lg shadow-md border">
          <h3 className="font-semibold mb-4 text-lg">Security Overview</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Security Officers</span>
              <span className="text-lg font-semibold text-primary">89</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Communities</span>
              <span className="text-lg font-semibold text-primary">156</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Response Time</span>
              <span className="text-lg font-semibold text-green-600">2.4 min</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Premium Users</span>
              <span className="text-lg font-semibold text-blue-600">67%</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Active Alerts</span>
              <span className="text-lg font-semibold text-orange-600">12</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Resolved Today</span>
              <span className="text-lg font-semibold text-green-600">45</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Total SOS Calls</span>
              <span className="text-lg font-semibold text-red-600">23</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Coverage Areas</span>
              <span className="text-lg font-semibold text-purple-600">28</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Online Officers</span>
              <span className="text-lg font-semibold text-cyan-600">76</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Avg. Resolution</span>
              <span className="text-lg font-semibold text-teal-600">8.5 min</span>
            </div>
          </div>
        </div>
        <div className="bg-card p-6 rounded-lg shadow-md border flex flex-col">
          <h3 className="font-semibold mb-4 text-lg">Recent Activity</h3>
          <div className="space-y-3 overflow-y-auto max-h-96 pr-2 scrollbar-thin scrollbar-thumb-gray-300 scrollbar-track-gray-100">
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">New user registered</p>
                <p className="text-xs text-muted-foreground">2 minutes ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-blue-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Geofence created</p>
                <p className="text-xs text-muted-foreground">15 minutes ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-orange-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Security alert resolved</p>
                <p className="text-xs text-muted-foreground">1 hour ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-red-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">SOS alert triggered</p>
                <p className="text-xs text-muted-foreground">1 hour ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-purple-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Sub-admin assigned</p>
                <p className="text-xs text-muted-foreground">2 hours ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-yellow-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Community message sent</p>
                <p className="text-xs text-muted-foreground">3 hours ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-pink-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Emergency notification</p>
                <p className="text-xs text-muted-foreground">4 hours ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-indigo-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Security officer joined</p>
                <p className="text-xs text-muted-foreground">5 hours ago</p>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <DailyAlertsChart />
        <UserActivityChart />
      </div>
      
      <RecentAlertsTable />
      </div>
    </div>
  );
}