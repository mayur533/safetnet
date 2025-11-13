import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface Incident {
  id: number;
  geofence: number;
  geofence_name?: string;
  officer?: number;
  officer_name?: string;
  incident_type: string;
  severity: string;
  title: string;
  details: string;
  location: object;
  is_resolved: boolean;
  resolved_at?: string | null;
  resolved_by?: number;
  resolved_by_username?: string;
  created_at: string;
  updated_at: string;
}

export interface IncidentCreateData {
  geofence: number;
  officer?: number;
  incident_type: string;
  severity: string;
  title: string;
  details: string;
  location?: object;
}

export interface IncidentUpdateData {
  geofence?: number;
  officer?: number;
  incident_type?: string;
  severity?: string;
  title?: string;
  details?: string;
  location?: object;
}

export const incidentsService = {
  /**
   * Get all incidents
   */
  async getAll(): Promise<Incident[]> {
    try {
      const response = await fetch(API_ENDPOINTS.INCIDENTS.LIST, {
        method: 'GET',
        headers: getAuthHeaders(),
      });

      // If backend returns 500 error (organization filtering issue), return empty array
      if (response.status === 500) {
        console.warn('Incidents API backend error - returning empty array');
        return [];
      }

      if (!response.ok) {
        throw new Error('Failed to fetch incidents');
      }

      const data = await response.json();
      // Handle paginated response - extract results array
      return data.results || data;
    } catch (error) {
      console.error('Error fetching incidents:', error);
      return []; // Return empty array to prevent crashes
    }
  },

  /**
   * Get a single incident
   */
  async getById(id: number): Promise<Incident> {
    const response = await fetch(API_ENDPOINTS.INCIDENTS.DETAIL(id), {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch incident');
    }

    return await response.json();
  },

  /**
   * Create a new incident
   */
  async create(data: IncidentCreateData): Promise<Incident> {
    const response = await fetch(API_ENDPOINTS.INCIDENTS.CREATE, {
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
   * Update an incident
   */
  async update(id: number, data: IncidentUpdateData): Promise<Incident> {
    const response = await fetch(API_ENDPOINTS.INCIDENTS.UPDATE(id), {
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
   * Resolve an incident
   */
  async resolve(id: number): Promise<Incident> {
    const response = await fetch(API_ENDPOINTS.INCIDENTS.RESOLVE(id), {
      method: 'POST',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(JSON.stringify(error));
    }

    return await response.json();
  },

  /**
   * Delete an incident
   */
  async delete(id: number): Promise<void> {
    const response = await fetch(API_ENDPOINTS.INCIDENTS.DELETE(id), {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to delete incident');
    }
  },
};

