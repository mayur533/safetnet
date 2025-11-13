import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface SubAdminProfile {
  id: number;
  user: {
    id: number;
    username: string;
    email: string;
    role: string;
    is_active: boolean;
  };
  permissions: 'READ_ONLY' | 'READ_WRITE' | 'FULL_ACCESS';
  assigned_scope: 'GLOBAL' | 'REGIONAL' | 'LOCAL';
  is_active: boolean;
  created_by?: number;
  created_at: string;
  updated_at: string;
}

export interface SubAdminCreateData {
  username: string;
  email: string;
  password: string;
  full_name?: string;
  permissions: 'READ_ONLY' | 'READ_WRITE' | 'FULL_ACCESS';
  assigned_scope: 'GLOBAL' | 'REGIONAL' | 'LOCAL';
}

export interface SubAdminUpdateData {
  permissions?: 'READ_ONLY' | 'READ_WRITE' | 'FULL_ACCESS';
  assigned_scope?: 'GLOBAL' | 'REGIONAL' | 'LOCAL';
  is_active?: boolean;
}

export const subadminsService = {
  /**
   * Get all sub-admins
   */
  async getAll(): Promise<SubAdminProfile[]> {
    const response = await fetch(API_ENDPOINTS.SUB_ADMINS.LIST, {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch sub-admins');
    }

    const data = await response.json();
    // Handle paginated response - extract results array
    return data.results || data;
  },

  /**
   * Get a single sub-admin
   */
  async getById(id: number): Promise<SubAdminProfile> {
    const response = await fetch(API_ENDPOINTS.SUB_ADMINS.DETAIL(id), {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch sub-admin');
    }

    return await response.json();
  },

  /**
   * Create a new sub-admin
   */
  async create(data: SubAdminCreateData): Promise<SubAdminProfile> {
    const response = await fetch(API_ENDPOINTS.SUB_ADMINS.CREATE, {
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
   * Update a sub-admin
   */
  async update(id: number, data: SubAdminUpdateData): Promise<SubAdminProfile> {
    const response = await fetch(API_ENDPOINTS.SUB_ADMINS.UPDATE(id), {
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
   * Delete a sub-admin
   */
  async delete(id: number): Promise<void> {
    const response = await fetch(API_ENDPOINTS.SUB_ADMINS.DELETE(id), {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to delete sub-admin');
    }
  },
};

