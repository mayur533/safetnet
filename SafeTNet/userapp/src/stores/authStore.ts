import {create} from 'zustand';
import {User} from '../models/user.types';
import {mockUser} from '../services/mockData';

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: false,
            login: async (email: string, password: string) => {
            await new Promise<void>((resolve) => setTimeout(() => resolve(), 1000));
            set({user: mockUser, isAuthenticated: true});
          },
  logout: () => {
    set({user: null, isAuthenticated: false});
  },
}));
