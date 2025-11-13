import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface Promocode {
  id: number;
  code: string;
  discount_percentage: number;
  expiry_date: string;
  is_active: boolean;
  is_valid?: boolean;
  created_at: string;
  updated_at: string;
}

export interface PromocodeCreateData {
  code: string;
  discount_percentage: number;
  expiry_date: string;
  is_active?: boolean;
}

export interface PromocodeUpdateData {
  code?: string;
  discount_percentage?: number;
  expiry_date?: string;
  is_active?: boolean;
}

export const promocodesService = {
  /**
   * Get all promocodes
   */
  async getAll(): Promise<Promocode[]> {
    const response = await fetch(API_ENDPOINTS.PROMOCODES.LIST, {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch promocodes');
    }

    const data = await response.json();
    // Handle paginated response - extract results array
    return data.results || data;
  },

  /**
   * Get a single promocode
   */
  async getById(id: number): Promise<Promocode> {
    const response = await fetch(API_ENDPOINTS.PROMOCODES.DETAIL(id), {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch promocode');
    }

    return await response.json();
  },

  /**
   * Create a new promocode
   */
  async create(data: PromocodeCreateData): Promise<Promocode> {
    const response = await fetch(API_ENDPOINTS.PROMOCODES.CREATE, {
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
   * Update a promocode
   */
  async update(id: number, data: PromocodeUpdateData): Promise<Promocode> {
    const response = await fetch(API_ENDPOINTS.PROMOCODES.UPDATE(id), {
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
   * Delete a promocode
   */
  async delete(id: number): Promise<void> {
    const response = await fetch(API_ENDPOINTS.PROMOCODES.DELETE(id), {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to delete promocode');
    }
  },
};

