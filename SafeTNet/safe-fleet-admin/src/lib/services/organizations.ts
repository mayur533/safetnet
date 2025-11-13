import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface Organization {
  id: number;
  name: string;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface OrganizationCreateData {
  name: string;
  description?: string;
}

export interface OrganizationUpdateData {
  name?: string;
  description?: string;
}

export const organizationsService = {
  /**
   * Get all organizations
   */
  async getAll(): Promise<Organization[]> {
    // Check if user should have access
    try {
      const response = await fetch(API_ENDPOINTS.ORGANIZATIONS.LIST, {
        method: 'GET',
        headers: getAuthHeaders(),
      });

      if (!response.ok) {
        // Return empty array for 403 errors (Sub-Admins don't have access)
        if (response.status === 403) {
          return [];
        }
        throw new Error('Failed to fetch organizations');
      }

      const data = await response.json();
      return data.results || data;
    } catch {
      // Return empty array instead of throwing
      // Silently fail - this is expected for users without access
      return [];
    }
  },

  /**
   * Get a single organization
   */
  async getById(id: number): Promise<Organization> {
    const response = await fetch(API_ENDPOINTS.ORGANIZATIONS.DETAIL(id), {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch organization with ID ${id}`);
    }

    return response.json();
  },

  /**
   * Create a new organization
   */
  async create(data: OrganizationCreateData): Promise<Organization> {
    const response = await fetch(API_ENDPOINTS.ORGANIZATIONS.CREATE, {
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
   * Update an organization
   */
  async update(id: number, data: OrganizationUpdateData): Promise<Organization> {
    const response = await fetch(API_ENDPOINTS.ORGANIZATIONS.UPDATE(id), {
      method: 'PUT',
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
   * Delete an organization
   */
  async delete(id: number): Promise<void> {
    const response = await fetch(API_ENDPOINTS.ORGANIZATIONS.DELETE(id), {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to delete organization');
    }
  },
};

