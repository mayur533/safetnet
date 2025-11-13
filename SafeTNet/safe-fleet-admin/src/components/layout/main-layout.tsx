'use client';

import { Header } from './header';
import { Sidebar } from './sidebar';
import { SearchProvider } from '@/lib/contexts/search-context';
import { useAuth } from '@/lib/contexts/auth-context';
import { getNavigationByRole } from '@/lib/config/navigation';

interface MainLayoutProps {
  children: React.ReactNode;
}

export function MainLayout({ children }: MainLayoutProps) {
  const { user } = useAuth();
  
  // Get navigation based on user role
  const navigation = user ? getNavigationByRole(user.role) : [];
  
  // Determine sidebar title and subtitle based on role
  const isSubAdmin = user?.role.toUpperCase().replace(/_/g, ' ').includes('SUB');
  const sidebarTitle = 'SafeTNet';
  const sidebarSubtitle = isSubAdmin ? 'Sub-Admin Panel' : 'Admin Panel';
  
  return (
    <SearchProvider>
      <div className="flex h-screen bg-background text-foreground">
        <Sidebar 
          navigation={navigation} 
          title={sidebarTitle}
          subtitle={sidebarSubtitle}
        />
        <main className="flex-1 p-8 overflow-y-auto">
          <Header />
          {children}
        </main>
      </div>
    </SearchProvider>
  );
}
