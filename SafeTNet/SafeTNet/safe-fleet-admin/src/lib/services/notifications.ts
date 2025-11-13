import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface Notification {
  id: number;
  notification_type: 'NORMAL' | 'EMERGENCY';
  title: string;
  message: string;
  target_type: string;
  target_geofence?: number;
  target_geofence_name?: string;
  target_geofences?: number[];
  target_geofences_names?: Array<{id: number; name: string}>;
  target_officers?: number[];
  target_officers_names?: string[];
  organization: number;
  organization_name?: string;
  is_sent: boolean;
  sent_at?: string;
  created_by: number;
  created_by_username?: string;
  created_at: string;
  updated_at: string;
  read_users?: number[];
  is_read?: boolean;
}

export interface NotificationCreateData {
  notification_type: 'NORMAL' | 'EMERGENCY';
  title: string;
  message: string;
  target_type: string;
  target_geofence?: number;
  target_officers?: number[];
}

export interface NotificationSendData {
  notification_type: 'NORMAL' | 'EMERGENCY';
  title: string;
  message: string;
  target_type: string;
  target_geofence?: number;
  target_geofence_ids?: number[];
}

export const notificationsService = {
  /**
   * Get all notifications
   */
  async getAll(): Promise<Notification[]> {
    const response = await fetch(API_ENDPOINTS.NOTIFICATIONS.LIST, {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch notifications');
    }

    const data = await response.json();
    // Handle paginated response - extract results array
    return data.results || data;
  },

  /**
   * Get a single notification
   */
  async getById(id: number): Promise<Notification> {
    const response = await fetch(API_ENDPOINTS.NOTIFICATIONS.DETAIL(id), {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch notification');
    }

    return await response.json();
  },

  /**
   * Create a new notification
   */
  async create(data: NotificationCreateData): Promise<Notification> {
    const response = await fetch(API_ENDPOINTS.NOTIFICATIONS.CREATE, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(JSON.stringify(error));
    }

    return await response.json();
  },

  /**
   * Send a notification (Sub-Admin specific endpoint)
   */
  async send(data: NotificationSendData): Promise<Notification> {
    const response = await fetch(API_ENDPOINTS.NOTIFICATIONS.SEND, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(JSON.stringify(error));
    }

    return await response.json();
  },

  /**
   * Mark notification as read
   */
  async markAsRead(id: number): Promise<void> {
    const response = await fetch(API_ENDPOINTS.NOTIFICATIONS.MARK_READ(id), {
      method: 'POST',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to mark notification as read');
    }
  },

  /**
   * Delete a notification
   */
  async delete(id: number): Promise<void> {
    const response = await fetch(API_ENDPOINTS.NOTIFICATIONS.DELETE(id), {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to delete notification');
    }
  },
};

