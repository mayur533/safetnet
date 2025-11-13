import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface UserDetail {
  id: number;
  user: {
    id: number;
    username: string;
    email: string;
    full_name?: string;
  };
  phone_number?: string;
  address?: string;
  city?: string;
  state?: string;
  zip_code?: string;
  country?: string;
  date_of_birth?: string;
  profile_image?: string;
  bio?: string;
  preferences?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export const userDetailsService = {
  /**
   * Get all user details
   */
  async getAll(): Promise<UserDetail[]> {
    const response = await fetch(API_ENDPOINTS.USER_DETAILS.LIST, {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch user details');
    }

    const data = await response.json();
    return data.results || data;
  },

  /**
   * Get user details for a specific user
   */
  async getByUserId(userId: number): Promise<UserDetail | null> {
    try {
      const response = await fetch(`${API_ENDPOINTS.USER_DETAILS.LIST}?user=${userId}`, {
        method: 'GET',
        headers: getAuthHeaders(),
      });

      if (!response.ok) {
        if (response.status === 404) {
          return null; // No details found for this user
        }
        throw new Error('Failed to fetch user details');
      }

      const data = await response.json();
      const results = data.results || data;
      return results.length > 0 ? results[0] : null;
    } catch (error) {
      console.error('Error fetching user details:', error);
      return null;
    }
  },

  /**
   * Get a single user detail by ID
   */
  async getById(id: number): Promise<UserDetail> {
    const response = await fetch(API_ENDPOINTS.USER_DETAILS.DETAIL(id), {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch user detail with ID ${id}`);
    }

    return response.json();
  },
};










