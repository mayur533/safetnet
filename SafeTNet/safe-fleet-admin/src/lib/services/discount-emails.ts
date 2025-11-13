import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface DiscountEmail {
  id: number;
  email: string;
  discount_code: number;
  discount_code_code?: string;
  discount_code_discount?: string;
  status: 'PENDING' | 'SENT';
  created_at: string;
}

export interface DiscountEmailCreateData {
  email: string;
  discount_code: number;
}

export const discountEmailsService = {
  /**
   * Get all discount emails
   */
  async getAll(): Promise<DiscountEmail[]> {
    const response = await fetch(API_ENDPOINTS.DISCOUNT_EMAILS.LIST, {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch discount emails');
    }

    const data = await response.json();
    return data.results || data;
  },

  /**
   * Get a single discount email
   */
  async getById(id: number): Promise<DiscountEmail> {
    const response = await fetch(API_ENDPOINTS.DISCOUNT_EMAILS.DETAIL(id), {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch discount email with ID ${id}`);
    }

    return response.json();
  },

  /**
   * Send a new discount email
   */
  async send(data: DiscountEmailCreateData): Promise<DiscountEmail> {
    const response = await fetch(API_ENDPOINTS.DISCOUNT_EMAILS.CREATE, {
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
};

