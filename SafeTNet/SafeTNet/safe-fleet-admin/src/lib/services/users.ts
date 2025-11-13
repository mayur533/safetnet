import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface User {
  id: number;
  username: string;
  email: string;
  first_name?: string;
  last_name?: string;
  full_name?: string; // Computed field (first_name + last_name)
  role: string;
  organization?: {
    id: number;
    name: string;
  } | null;
  is_active: boolean;
  date_joined: string;
  last_login?: string | null;
  status?: 'active' | 'inactive'; // For backwards compatibility
}

export interface UserUpdateData {
  username?: string;
  email?: string;
  first_name?: string;
  last_name?: string;
  role?: string;
  is_active?: boolean;
  organization?: number | null;
}

export interface UserCreateData {
  username: string;
  email: string;
  password: string;
  full_name?: string;
  role?: string;
  first_name?: string;
  last_name?: string;
  organization?: number | null;
}

export const usersService = {
  /**
   * Get all users
   */
  async getAll(): Promise<User[]> {
    const allUsers: User[] = [];
    let nextUrl: string | null = API_ENDPOINTS.USERS.LIST;

    while (nextUrl) {
      const response: Response = await fetch(nextUrl, {
        method: 'GET',
        headers: getAuthHeaders(),
      });

      if (!response.ok) {
        throw new Error('Failed to fetch users');
      }

      const data = await response.json();
      
      // Handle paginated response
      if (data.results) {
        allUsers.push(...data.results);
        nextUrl = data.next;
      } else {
        // Not paginated, return the data directly
        return Array.isArray(data) ? data : [];
      }
    }

    return allUsers;
  },

  /**
   * Get a single user
   */
  async getById(id: number): Promise<User> {
    const response = await fetch(API_ENDPOINTS.USERS.DETAIL(id), {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch user');
    }

    return await response.json();
  },

  /**
   * Create a new user
   */
  async create(data: UserCreateData): Promise<User> {
    const response = await fetch(API_ENDPOINTS.USERS.LIST, {
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
   * Update a user
   */
  async update(id: number, data: UserUpdateData): Promise<User> {
    const response = await fetch(API_ENDPOINTS.USERS.UPDATE(id), {
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
   * Delete a user
   */
  async delete(id: number): Promise<void> {
    const response = await fetch(API_ENDPOINTS.USERS.DELETE(id), {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to delete user');
    }
  },
};

