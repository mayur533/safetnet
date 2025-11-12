import api from './api';
import { Alert, PaginatedResponse } from '../types';

export const alertService = {
  // Get paginated list of Alerts
  getAlerts: async (params?: {
    page?: number;
    page_size?: number;
    search?: string;
    alert_type?: string;
    severity?: string;
    is_resolved?: boolean;
    geofence?: number;
    ordering?: string;
  }): Promise<PaginatedResponse<Alert>> => {
    const response = await api.get('/auth/admin/alerts/', { params });
    return response.data;
  },

  // Get single Alert by ID
  getAlert: async (id: number): Promise<Alert> => {
    const response = await api.get(`/auth/admin/alerts/${id}/`);
    return response.data;
  },

  // Create new Alert
  createAlert: async (data: Partial<Alert>): Promise<Alert> => {
    const response = await api.post('/auth/admin/alerts/', data);
    return response.data;
  },

  // Update Alert
  updateAlert: async (id: number, data: Partial<Alert>): Promise<Alert> => {
    const response = await api.put(`/auth/admin/alerts/${id}/`, data);
    return response.data;
  },

  // Partial update Alert
  patchAlert: async (id: number, data: Partial<Alert>): Promise<Alert> => {
    const response = await api.patch(`/auth/admin/alerts/${id}/`, data);
    return response.data;
  },

  // Delete Alert
  deleteAlert: async (id: number): Promise<void> => {
    await api.delete(`/auth/admin/alerts/${id}/`);
  },
};
