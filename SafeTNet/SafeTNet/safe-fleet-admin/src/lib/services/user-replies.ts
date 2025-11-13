import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface UserReply {
  id: number;
  user: {
    id: number;
    username: string;
    email: string;
    full_name?: string;
  };
  subject: string;
  message: string;
  reply_type: string;
  status: 'PENDING' | 'REVIEWED' | 'RESOLVED';
  created_at: string;
  updated_at: string;
}

export const userRepliesService = {
  /**
   * Get all user replies
   */
  async getAll(): Promise<UserReply[]> {
    const response = await fetch(API_ENDPOINTS.USER_REPLIES.LIST, {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch user replies');
    }

    const data = await response.json();
    return data.results || data;
  },

  /**
   * Get user replies for a specific user
   */
  async getByUserId(userId: number): Promise<UserReply[]> {
    const response = await fetch(`${API_ENDPOINTS.USER_REPLIES.LIST}?user=${userId}`, {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch user replies');
    }

    const data = await response.json();
    return data.results || data;
  },

  /**
   * Get a single user reply by ID
   */
  async getById(id: number): Promise<UserReply> {
    const response = await fetch(API_ENDPOINTS.USER_REPLIES.DETAIL(id), {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch user reply with ID ${id}`);
    }

    return response.json();
  },
};





















