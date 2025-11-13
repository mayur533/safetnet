import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface Alert {
  id: number;
  alert_type: string;
  message: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  location?: string;
  user?: number;
  user_username?: string;
  geofence?: number;
  geofence_name?: string;
  is_resolved: boolean;
  resolved_by?: number;
  resolved_by_username?: string;
  resolved_at?: string;
  response_time?: number;
  created_at: string;
  updated_at: string;
}

export const alertsService = {
  /**
   * Get all alerts
   */
  async getAll(): Promise<Alert[]> {
    const response = await fetch(API_ENDPOINTS.ALERTS.LIST, {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch alerts');
    }

    const data = await response.json();
    return data.results || data;
  },

  /**
   * Get a single alert
   */
  async getById(id: number): Promise<Alert> {
    const response = await fetch(API_ENDPOINTS.ALERTS.DETAIL(id), {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch alert with ID ${id}`);
    }

    return response.json();
  },

  /**
   * Resolve an alert
   */
  async resolve(id: number): Promise<Alert> {
    const response = await fetch(API_ENDPOINTS.ALERTS.RESOLVE(id), {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ is_resolved: true }),
    });

    if (!response.ok) {
      throw new Error('Failed to resolve alert');
    }

    return await response.json();
  },

  /**
   * Delete an alert
   */
  async delete(id: number): Promise<void> {
    const response = await fetch(API_ENDPOINTS.ALERTS.DELETE(id), {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to delete alert');
    }
  },
};























