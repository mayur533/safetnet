'use client';

import { usePathname } from 'next/navigation';
import { MainLayout } from './main-layout';
import { ProtectedRoute } from '@/components/auth/protected-route';

interface ConditionalLayoutProps {
  children: React.ReactNode;
}

export function ConditionalLayout({ children }: ConditionalLayoutProps) {
  const pathname = usePathname();
  
  // Auth pages that should not have sidebar/header
  const authPages = ['/login', '/register', '/forgot-password', '/reset-password'];
  
  const isAuthPage = authPages.includes(pathname);
  
  return (
    <ProtectedRoute>
      {isAuthPage ? (
        <>{children}</>
      ) : (
        <MainLayout>{children}</MainLayout>
      )}
    </ProtectedRoute>
  );
}
