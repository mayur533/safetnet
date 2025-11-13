import api from './api';
import { 
  UserListItem, 
  PaginatedResponse 
} from '../types';

export const userService = {
  // Get paginated list of Users
  getUsers: async (params?: {
    page?: number;
    page_size?: number;
    search?: string;
    role?: string;
    organization?: number;
    is_active?: boolean;
    ordering?: string;
  }): Promise<PaginatedResponse<UserListItem>> => {
    const response = await api.get('/auth/admin/users/', { params });
    return response.data;
  },
};
