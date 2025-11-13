import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface AnalyticsData {
  total_users: number;
  active_users: number;
  total_geofences: number;
  active_geofences: number;
  total_alerts: number;
  alerts_today: number;
  critical_alerts: number;
  alerts_last_30_days: number;
  avg_response_time: number;
  resolution_rate: number;
}

export const analyticsService = {
  /**
   * Get analytics data
   */
  async getAnalytics(): Promise<AnalyticsData> {
    const response = await fetch(API_ENDPOINTS.ANALYTICS.DATA, {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch analytics data');
    }

    return await response.json();
  },
};

