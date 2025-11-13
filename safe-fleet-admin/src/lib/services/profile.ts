import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

interface UserProfile {
  id: number;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  date_joined: string;
}

interface UpdateProfileData {
  username?: string;
  email?: string;
  full_name?: string;
}

interface ChangePasswordData {
  old_password: string;
  new_password: string;
  confirm_password: string;
}

export const profileService = {
  /**
   * Get current user profile
   */
  async getProfile(): Promise<UserProfile> {
    const response = await fetch(API_ENDPOINTS.AUTH.PROFILE, {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to fetch profile');
    }

    return await response.json();
  },

  /**
   * Update user profile
   */
  async updateProfile(data: UpdateProfileData): Promise<UserProfile> {
    const response = await fetch(API_ENDPOINTS.AUTH.PROFILE, {
      method: 'PUT',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(JSON.stringify(error) || 'Failed to update profile');
    }

    const updatedProfile = await response.json();
    
    // Update user in storage
    if (typeof window !== 'undefined') {
      const storage = localStorage.getItem('user') ? localStorage : sessionStorage;
      storage.setItem('user', JSON.stringify(updatedProfile));
    }

    return updatedProfile;
  },

  /**
   * Change password
   */
  async changePassword(data: ChangePasswordData): Promise<{ message: string }> {
    const response = await fetch(`${API_ENDPOINTS.AUTH.PROFILE}change-password/`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(JSON.stringify(error) || 'Failed to change password');
    }

    return await response.json();
  },
};


























