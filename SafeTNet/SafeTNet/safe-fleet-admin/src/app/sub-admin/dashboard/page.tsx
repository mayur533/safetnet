'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';
import { GeofencesMap } from '@/components/dashboard/geofences-map';
import { DailyAlertsChart } from '@/components/dashboard/daily-alerts-chart';
import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';
import { CardLoading } from '@/components/ui/content-loading';

interface SubAdminKPIs {
  active_geofences: number;
  total_officers: number;
  active_officers: number;
  incidents_today: number;
  unresolved_incidents: number;
  critical_incidents: number;
  notifications_sent_today: number;
  organization_name?: string;
}

export default function SubAdminDashboardPage() {
  const router = useRouter();
  const [kpis, setKpis] = useState<SubAdminKPIs>({
    active_geofences: 0,
    total_officers: 0,
    active_officers: 0,
    incidents_today: 0,
    unresolved_incidents: 0,
    critical_incidents: 0,
    notifications_sent_today: 0,
  });
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchKPIs();
  }, []);

  const fetchKPIs = async () => {
    try {
      setIsLoading(true);
      const response = await fetch(API_ENDPOINTS.SUBADMIN.DASHBOARD_KPIS, {
        method: 'GET',
        headers: getAuthHeaders(),
      });

      if (response.ok) {
        const data = await response.json();
        setKpis(data);
      } else if (response.status === 403) {
        console.log('Sub-Admin KPI endpoint requires SUB_ADMIN role with organization. Showing default values.');
        toast.error('Access Denied: You need an assigned organization to view this dashboard. Please contact your administrator.');
      }
    } catch (error) {
      console.error('Failed to fetch KPIs:', error);
    } finally {
      setIsLoading(false);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold">My Area Dashboard</h1>
          <div className="text-sm text-muted-foreground">
            Regional Overview
          </div>
        </div>

        {/* Stats Loading */}
        <CardLoading count={4} />

        {/* Map and Stats Loading */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 bg-card rounded-lg shadow-md border overflow-hidden" style={{ height: '500px' }}>
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-primary mb-4"></div>
                <p className="text-sm text-muted-foreground">Loading map...</p>
              </div>
            </div>
          </div>
          
          <div className="bg-card p-6 rounded-lg shadow-md border">
            <div className="h-6 w-32 bg-muted rounded mb-4 animate-pulse"></div>
            <div className="space-y-3">
              {Array.from({ length: 8 }).map((_, i) => (
                <div key={i} className="flex items-center justify-between animate-pulse" style={{ animationDelay: `${i * 50}ms` }}>
                  <div className="h-3 w-32 bg-muted/60 rounded"></div>
                  <div className="h-4 w-12 bg-muted rounded"></div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Chart Loading */}
        <div className="bg-card p-6 rounded-lg shadow-md border">
          <div className="h-6 w-40 bg-muted rounded mb-4 animate-pulse"></div>
          <div className="h-64 bg-muted/40 rounded animate-pulse"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">My Area Dashboard</h1>
        <div className="text-sm text-muted-foreground">
          Regional Overview
        </div>
      </div>

      {/* Stats Cards - Local Area Only */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="bg-gradient-to-br from-blue-500 to-blue-600 p-6 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-blue-100">My Geofences</p>
                <h3 className="text-3xl font-bold mt-1">{kpis.active_geofences}</h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '48px' }}>
                public
              </span>
            </div>
            <p className="text-xs text-blue-100 mt-2">Active in your organization</p>
          </div>

          <div className="bg-gradient-to-br from-indigo-500 to-indigo-600 p-6 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-indigo-100">Security Officers</p>
                <h3 className="text-3xl font-bold mt-1">{kpis.total_officers}</h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '48px' }}>
                security
              </span>
            </div>
            <p className="text-xs text-indigo-100 mt-2">{kpis.active_officers} active now</p>
          </div>

          <div className="bg-gradient-to-br from-orange-500 to-orange-600 p-6 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-orange-100">Unresolved Incidents</p>
                <h3 className="text-3xl font-bold mt-1">{kpis.unresolved_incidents}</h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '48px' }}>
                warning
              </span>
            </div>
            <p className="text-xs text-orange-100 mt-2">{kpis.critical_incidents} critical</p>
          </div>

          <div className="bg-gradient-to-br from-red-500 to-red-600 p-6 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-red-100">Incidents Today</p>
                <h3 className="text-3xl font-bold mt-1">{kpis.incidents_today}</h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '48px' }}>
                report
              </span>
            </div>
            <p className="text-xs text-red-100 mt-2">{kpis.notifications_sent_today} notifications sent</p>
          </div>
      </div>

      {/* Map and Quick Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <GeofencesMap />
        </div>
        
        <div className="bg-card p-6 rounded-lg shadow-md border">
          <h3 className="font-semibold mb-4 text-lg">Area Statistics</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Total Coverage</span>
              <span className="text-lg font-semibold text-primary">12.5 km²</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Residents</span>
              <span className="text-lg font-semibold text-blue-600">2,847</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Response Time</span>
              <span className="text-lg font-semibold text-green-600">3.2 min</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Officers Online</span>
              <span className="text-lg font-semibold text-cyan-600">18/24</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Emergency Alerts</span>
              <span className="text-lg font-semibold text-red-600">2</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Normal Alerts</span>
              <span className="text-lg font-semibold text-orange-600">3</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Patrols Active</span>
              <span className="text-lg font-semibold text-purple-600">6</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Checkpoints</span>
              <span className="text-lg font-semibold text-indigo-600">15</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Activity and Alerts Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <DailyAlertsChart />
        
        <div className="bg-card p-6 rounded-lg shadow-md border flex flex-col">
          <h3 className="font-semibold mb-4 text-lg">Recent Activity</h3>
          <div className="space-y-3 overflow-y-auto max-h-96 pr-2">
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Officer John assigned to North Gate</p>
                <p className="text-xs text-muted-foreground">5 minutes ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-blue-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">New geofence created: Park Area</p>
                <p className="text-xs text-muted-foreground">20 minutes ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-orange-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Alert resolved: Suspicious activity</p>
                <p className="text-xs text-muted-foreground">45 minutes ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-red-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Emergency alert: Medical assistance</p>
                <p className="text-xs text-muted-foreground">1 hour ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-purple-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Patrol completed: East Sector</p>
                <p className="text-xs text-muted-foreground">2 hours ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-yellow-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Notification sent to residents</p>
                <p className="text-xs text-muted-foreground">3 hours ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-pink-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Officer shift change</p>
                <p className="text-xs text-muted-foreground">4 hours ago</p>
              </div>
            </div>
            <div className="flex items-start space-x-3">
              <div className="w-2 h-2 bg-indigo-500 rounded-full mt-2 flex-shrink-0"></div>
              <div className="flex-1">
                <p className="text-sm font-medium">Checkpoint inspection completed</p>
                <p className="text-xs text-muted-foreground">5 hours ago</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-card p-6 rounded-lg shadow-md border">
        <h3 className="font-semibold mb-4 text-lg">Quick Actions</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <button 
            onClick={() => router.push('/sub-admin/geofences?create=true')}
            className="flex flex-col items-center justify-center p-4 rounded-lg border hover:bg-muted/50 transition-colors"
          >
            <span className="material-icons-outlined text-primary mb-2" style={{ fontSize: '32px' }}>
              add_location
            </span>
            <span className="text-sm font-medium">Create Geofence</span>
          </button>
          <button 
            onClick={() => router.push('/sub-admin/officers?add=true')}
            className="flex flex-col items-center justify-center p-4 rounded-lg border hover:bg-muted/50 transition-colors"
          >
            <span className="material-icons-outlined text-blue-600 mb-2" style={{ fontSize: '32px' }}>
              person_add
            </span>
            <span className="text-sm font-medium">Add Officer</span>
          </button>
          <button 
            onClick={() => router.push('/sub-admin/notifications')}
            className="flex flex-col items-center justify-center p-4 rounded-lg border hover:bg-muted/50 transition-colors"
          >
            <span className="material-icons-outlined text-orange-600 mb-2" style={{ fontSize: '32px' }}>
              notifications_active
            </span>
            <span className="text-sm font-medium">Send Alert</span>
          </button>
          <button 
            onClick={() => router.push('/sub-admin/incidents')}
            className="flex flex-col items-center justify-center p-4 rounded-lg border hover:bg-muted/50 transition-colors"
          >
            <span className="material-icons-outlined text-green-600 mb-2" style={{ fontSize: '32px' }}>
              assessment
            </span>
            <span className="text-sm font-medium">View Reports</span>
          </button>
        </div>
      </div>
    </div>
  );
}
