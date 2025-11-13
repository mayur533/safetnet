import { create } from 'zustand';
import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface DashboardStats {
  totalSubAdmins: number;
  activeGeofences: number;
  activeUsers: number;
  totalAlerts: number;
}

export interface DashboardKPIResponse {
  active_geofences: number;
  alerts_today: number;
  active_sub_admins: number;
  total_users: number;
  critical_alerts: number;
  system_health: string;
}

export interface Alert {
  id: string;
  time: string;
  location: string;
  type: string;
  status: 'pending' | 'critical' | 'resolved';
}

interface DashboardStore {
  stats: DashboardStats;
  alerts: Alert[];
  isLoading: boolean;
  fetchStats: () => Promise<void>;
  fetchAlerts: () => Promise<void>;
  updateAlertStatus: (id: string, status: Alert['status']) => void;
}

export const useDashboardStore = create<DashboardStore>((set) => ({
  stats: {
    totalSubAdmins: 0,
    activeGeofences: 0,
    activeUsers: 0,
    totalAlerts: 0,
  },
  alerts: [],
  isLoading: false,
  fetchStats: async () => {
    set({ isLoading: true });
    try {
      const response = await fetch(API_ENDPOINTS.DASHBOARD.KPIS, {
        method: 'GET',
        headers: getAuthHeaders(),
      });

      if (response.ok) {
        const data: DashboardKPIResponse = await response.json();
        
        set({
          stats: {
            totalSubAdmins: data.active_sub_admins || 0,
            activeGeofences: data.active_geofences || 0,
            activeUsers: data.total_users || 0,
            totalAlerts: data.alerts_today || 0,
          },
        });
      }
    } catch (error) {
      console.error('Failed to fetch dashboard stats:', error);
    } finally {
      set({ isLoading: false });
    }
  },
  fetchAlerts: async () => {
    set({ isLoading: true });
    try {
      const response = await fetch(API_ENDPOINTS.ALERTS.LIST, {
        method: 'GET',
        headers: getAuthHeaders(),
      });

      if (response.ok) {
        const data = await response.json();
        const alertsData = data.results || data;
        
        // Convert API alerts to dashboard format (show only recent 5)
        const recentAlerts: Alert[] = alertsData
          .slice(0, 5)
          .map((alert: unknown) => ({
            id: (alert as { id: number }).id.toString(),
            time: new Date((alert as { created_at: string }).created_at).toLocaleString('en-US', {
              month: 'short',
              day: 'numeric',
              hour: '2-digit',
              minute: '2-digit',
            }),
            location: (alert as { location?: string; geofence_name?: string }).location || (alert as { location?: string; geofence_name?: string }).geofence_name || 'N/A',
            type: (alert as { alert_type?: string }).alert_type || 'System Alert',
            status: (alert as { is_resolved?: boolean; severity?: string }).is_resolved ? 'resolved' : ((alert as { is_resolved?: boolean; severity?: string }).severity === 'critical' ? 'critical' : 'pending'),
          }));

        set({ alerts: recentAlerts });
      }
    } catch (error) {
      console.error('Failed to fetch dashboard alerts:', error);
      // Keep existing mock data on error
    } finally {
      set({ isLoading: false });
    }
  },
  updateAlertStatus: (id: string, status: Alert['status']) => {
    set(state => ({
      alerts: state.alerts.map(alert =>
        alert.id === id ? { ...alert, status } : alert
      ),
    }));
  },
}));
