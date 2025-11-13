import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface Geofence {
  id: number;
  name: string;
  description?: string;
  polygon_json: object;
  organization: number;
  organization_name?: string;
  active: boolean;
  created_by?: number;
  created_by_username?: string;
  created_at: string;
  updated_at: string;
  center_point?: [number, number];
}

export interface GeofenceCreateData {
  name: string;
  description?: string;
  polygon_json: object;
  organization: number;
  active?: boolean;
}

export interface GeofenceUpdateData {
  name?: string;
  description?: string;
  polygon_json?: object;
  active?: boolean;
}

export const geofencesService = {
  /**
   * Get all geofences
   */
  async getAll(): Promise<Geofence[]> {
    const response = await fetch(API_ENDPOINTS.GEOFENCES.LIST, {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch geofences');
    }

    const data = await response.json();
    // Handle paginated response - extract results array
    return data.results || data;
  },

  /**
   * Get a single geofence
   */
  async getById(id: number): Promise<Geofence> {
    const response = await fetch(API_ENDPOINTS.GEOFENCES.DETAIL(id), {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch geofence');
    }

    return await response.json();
  },

  /**
   * Create a new geofence
   */
  async create(data: GeofenceCreateData): Promise<Geofence> {
    const response = await fetch(API_ENDPOINTS.GEOFENCES.CREATE, {
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
   * Update a geofence
   */
  async update(id: number, data: GeofenceUpdateData): Promise<Geofence> {
    const response = await fetch(API_ENDPOINTS.GEOFENCES.UPDATE(id), {
      method: 'PATCH',
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
   * Delete a geofence
   */
  async delete(id: number): Promise<void> {
    const response = await fetch(API_ENDPOINTS.GEOFENCES.DELETE(id), {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to delete geofence');
    }
  },
};

