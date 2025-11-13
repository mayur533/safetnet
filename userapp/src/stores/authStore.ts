import {create} from 'zustand';
import {User} from '../models/user.types';
import {mockUser} from '../services/mockData';

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

// Sample user credentials for testing
const SAMPLE_EMAIL = 'user@example.com';
const SAMPLE_PASSWORD = 'password123';

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: false,
  login: async (email: string, password: string) => {
    await new Promise<void>((resolve) => setTimeout(() => resolve(), 1000));
    
    // Validate credentials
    if (email === SAMPLE_EMAIL && password === SAMPLE_PASSWORD) {
      set({user: mockUser, isAuthenticated: true});
    } else {
      throw new Error('Invalid email or password');
    }
  },
  logout: () => {
    set({user: null, isAuthenticated: false});
  },
}));
