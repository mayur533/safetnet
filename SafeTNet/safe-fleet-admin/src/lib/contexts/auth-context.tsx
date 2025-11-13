'use client';

import { createContext, useContext, useEffect, useState } from 'react';
import { useRouter, usePathname } from 'next/navigation';
import { authService } from '@/lib/services/auth';

interface User {
  id: number;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  date_joined: string;
}

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (user: User) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    // Check if user is authenticated on mount
    const checkAuth = () => {
      const storedUser = authService.getUser();
      const isAuth = authService.isAuthenticated();

      if (isAuth && storedUser) {
        setUser(storedUser as User);
      } else {
        setUser(null);
        // Redirect to login if not on public pages
        const publicPages = ['/login', '/register', '/forgot-password', '/reset-password'];
        if (!publicPages.includes(pathname)) {
          router.push('/login');
        }
      }
      setIsLoading(false);
    };

    checkAuth();
  }, [pathname, router]);

  const login = (userData: User) => {
    setUser(userData);
  };

  const logout = async () => {
    setUser(null);
    
    try {
      await authService.logout();
    } catch (error) {
      console.error('Logout error:', error);
    }
    
    // Use window.location for a hard redirect to clear all state
    if (typeof window !== 'undefined') {
      window.location.href = '/login';
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated: !!user,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

