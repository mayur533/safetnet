import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface SecurityOfficer {
  id: number;
  username?: string;
  name: string;
  contact: string;
  email?: string;
  assigned_geofence?: number;
  geofence_name?: string;
  organization: number;
  is_active: boolean;
  created_by?: number;
  created_at: string;
  updated_at: string;
}

export interface OfficerCreateData {
  username: string;
  name: string;
  contact: string;
  email?: string;
  password: string;
  assigned_geofence?: number;
  organization?: number; // Optional - auto-assigned by backend for Sub-Admin
  is_active?: boolean;
}

export interface OfficerUpdateData {
  username?: string;
  name?: string;
  contact?: string;
  email?: string;
  assigned_geofence?: number;
  is_active?: boolean;
}

export const officersService = {
  /**
   * Get all security officers
   */
  async getAll(): Promise<SecurityOfficer[]> {
    const response = await fetch(API_ENDPOINTS.OFFICERS.LIST, {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch security officers');
    }

    const data = await response.json();
    // Handle paginated response - extract results array
    return data.results || data;
  },

  /**
   * Get a single security officer
   */
  async getById(id: number): Promise<SecurityOfficer> {
    const response = await fetch(API_ENDPOINTS.OFFICERS.DETAIL(id), {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch security officer');
    }

    return await response.json();
  },

  /**
   * Create a new security officer
   */
  async create(data: OfficerCreateData): Promise<SecurityOfficer> {
    const response = await fetch(API_ENDPOINTS.OFFICERS.CREATE, {
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
   * Update a security officer
   */
  async update(id: number, data: OfficerUpdateData): Promise<SecurityOfficer> {
    const response = await fetch(API_ENDPOINTS.OFFICERS.UPDATE(id), {
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
   * Delete a security officer
   */
  async delete(id: number): Promise<void> {
    const response = await fetch(API_ENDPOINTS.OFFICERS.DELETE(id), {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to delete security officer');
    }
  },
};

