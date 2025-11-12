import api from './api';
import { 
  Geofence, 
  GeofenceCreateRequest, 
  GeofenceUpdateRequest, 
  PaginatedResponse 
} from '../types';

export const geofenceService = {
  // Get paginated list of Geofences
  getGeofences: async (params?: {
    page?: number;
    page_size?: number;
    search?: string;
    organization?: number;
    active?: boolean;
    ordering?: string;
  }): Promise<PaginatedResponse<Geofence>> => {
    const response = await api.get('/auth/admin/geofences/', { params });
    return response.data;
  },

  // Get single Geofence by ID
  getGeofence: async (id: number): Promise<Geofence> => {
    const response = await api.get(`/auth/admin/geofences/${id}/`);
    return response.data;
  },

  // Create new Geofence
  createGeofence: async (data: GeofenceCreateRequest): Promise<Geofence> => {
    const response = await api.post('/auth/admin/geofences/', data);
    return response.data;
  },

  // Update Geofence
  updateGeofence: async (id: number, data: GeofenceUpdateRequest): Promise<Geofence> => {
    const response = await api.put(`/auth/admin/geofences/${id}/`, data);
    return response.data;
  },

  // Partial update Geofence
  patchGeofence: async (id: number, data: Partial<GeofenceUpdateRequest>): Promise<Geofence> => {
    const response = await api.patch(`/auth/admin/geofences/${id}/`, data);
    return response.data;
  },

  // Delete Geofence
  deleteGeofence: async (id: number): Promise<void> => {
    await api.delete(`/auth/admin/geofences/${id}/`);
  },
};
