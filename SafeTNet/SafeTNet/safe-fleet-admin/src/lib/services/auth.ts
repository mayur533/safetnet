import { API_ENDPOINTS, STORAGE_KEYS, DEFAULT_HEADERS } from '@/lib/config/api';

interface LoginCredentials {
  username: string;
  password: string;
  rememberMe?: boolean;
}

interface RegisterData {
  username: string;
  email: string;
  password: string;
  password_confirm: string;
  full_name?: string;
  role?: string;
  rememberMe?: boolean;
}

interface AuthResponse {
  access: string;
  refresh: string;
  user: {
    id: number;
    username: string;
    email: string;
    role: string;
    is_active: boolean;
    date_joined: string;
  };
}

// Helper to get the appropriate storage based on rememberMe
const getStorage = (rememberMe: boolean = false): Storage => {
  if (typeof window === 'undefined') {
    // Return a mock storage for SSR
    return {
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {},
      clear: () => {},
      key: () => null,
      length: 0,
    } as Storage;
  }
  return rememberMe ? localStorage : sessionStorage;
};

// Helper to check both storages for a key
const getFromStorage = (key: string): string | null => {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(key) || sessionStorage.getItem(key);
};

// Helper to remove from both storages
const removeFromBothStorages = (key: string) => {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(key);
  sessionStorage.removeItem(key);
};

export const authService = {
  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    const { rememberMe = false, ...loginData } = credentials;
    
    const response = await fetch(API_ENDPOINTS.AUTH.LOGIN, {
      method: 'POST',
      headers: DEFAULT_HEADERS,
      body: JSON.stringify(loginData),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Login failed');
    }

    const data = await response.json();
    
    // Store tokens based on rememberMe preference
    const storage = getStorage(rememberMe);
    if (typeof window !== 'undefined') {
      storage.setItem(STORAGE_KEYS.ACCESS_TOKEN, data.access);
      storage.setItem(STORAGE_KEYS.REFRESH_TOKEN, data.refresh);
      storage.setItem(STORAGE_KEYS.USER, JSON.stringify(data.user));
    }

    return data;
  },

  async register(data: RegisterData): Promise<AuthResponse> {
    const { rememberMe: _rememberMe, ...registerData } = data;
    
    const response = await fetch(API_ENDPOINTS.AUTH.REGISTER, {
      method: 'POST',
      headers: DEFAULT_HEADERS,
      body: JSON.stringify(registerData),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(JSON.stringify(error) || 'Registration failed');
    }

    const responseData = await response.json();
    
    // Don't store tokens during registration
    // User needs to login explicitly after registration
    
    return responseData;
  },

  async logout(): Promise<void> {
    const token = getFromStorage(STORAGE_KEYS.ACCESS_TOKEN);

    if (token) {
      try {
        await fetch(API_ENDPOINTS.AUTH.LOGOUT, {
          method: 'POST',
          headers: {
            ...DEFAULT_HEADERS,
            'Authorization': `Bearer ${token}`,
          },
        });
      } catch (error) {
        console.error('Logout API call failed:', error);
      }
    }

    // Clear tokens from both localStorage and sessionStorage
    if (typeof window !== 'undefined') {
      removeFromBothStorages(STORAGE_KEYS.ACCESS_TOKEN);
      removeFromBothStorages(STORAGE_KEYS.REFRESH_TOKEN);
      removeFromBothStorages(STORAGE_KEYS.USER);
    }
  },

  async refreshToken(): Promise<string> {
    const refreshToken = getFromStorage(STORAGE_KEYS.REFRESH_TOKEN);

    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const response = await fetch(API_ENDPOINTS.AUTH.REFRESH, {
      method: 'POST',
      headers: DEFAULT_HEADERS,
      body: JSON.stringify({ refresh: refreshToken }),
    });

    if (!response.ok) {
      throw new Error('Token refresh failed');
    }

    const data = await response.json();
    
    // Update access token in the same storage where refresh token was found
    if (typeof window !== 'undefined') {
      const storage = localStorage.getItem(STORAGE_KEYS.REFRESH_TOKEN) ? localStorage : sessionStorage;
      storage.setItem(STORAGE_KEYS.ACCESS_TOKEN, data.access);
    }

    return data.access;
  },

  getAccessToken(): string | null {
    return getFromStorage(STORAGE_KEYS.ACCESS_TOKEN);
  },

  getUser(): unknown | null {
    if (typeof window === 'undefined') return null;
    const user = getFromStorage(STORAGE_KEYS.USER);
    return user ? JSON.parse(user) : null;
  },

  isAuthenticated(): boolean {
    return !!this.getAccessToken();
  },

  async requestPasswordReset(email: string): Promise<{ message: string }> {
    const response = await fetch(API_ENDPOINTS.AUTH.REQUEST_RESET, {
      method: 'POST',
      headers: DEFAULT_HEADERS,
      body: JSON.stringify({ email }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || error.detail || 'Failed to send OTP');
    }

    return await response.json();
  },

  async resetPasswordWithOTP(email: string, otp: string, newPassword: string): Promise<{ message: string }> {
    const response = await fetch(API_ENDPOINTS.AUTH.RESET_PASSWORD, {
      method: 'POST',
      headers: DEFAULT_HEADERS,
      body: JSON.stringify({ email, otp, new_password: newPassword }),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || error.detail || 'Password reset failed');
    }

    return await response.json();
  },
};

