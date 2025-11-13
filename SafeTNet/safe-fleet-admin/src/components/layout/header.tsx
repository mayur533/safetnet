'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { NotificationDropdown } from './notification-dropdown';
import { useSearch } from '@/lib/contexts/search-context';
import { useAuth } from '@/lib/contexts/auth-context';
import { toast } from 'sonner';
import { Search, Person, Settings, Logout, ExpandMore } from '@mui/icons-material';

const searchPlaceholders: Record<string, string> = {
  '/': 'Search dashboard...',
  '/organizations': 'Search organizations...',
  '/sub-admins': 'Search sub-admins by name, email, or area...',
  '/users': 'Search users...',
  '/geofences': 'Search geofences...',
  '/alerts': 'Search alerts by type, severity, or status...',
  '/incidents': 'Search incidents by type, severity, or status...',
  '/notifications': 'Search notifications...',
  '/promocodes': 'Search promocodes by code or description...',
  '/discount-emails': 'Search discount emails...',
  '/analytics': 'Search analytics...',
  '/settings': 'Search settings...',
  '/profile': 'Search profile...',
  '/sub-admin/dashboard': 'Search dashboard...',
  '/sub-admin/geofences': 'Search geofences...',
  '/sub-admin/officers': 'Search officers by name, contact, or geofence...',
  '/sub-admin/incidents': 'Search incidents by type, severity, or status...',
  '/sub-admin/notifications': 'Search notifications...',
};

export function Header() {
  const pathname = usePathname();
  const router = useRouter();
  const { searchQuery, setSearchQuery } = useSearch();
  const { user, logout } = useAuth();
  const [isClient, setIsClient] = useState(false);
  
  const placeholder = searchPlaceholders[pathname] || 'Search...';

  useEffect(() => {
    setIsClient(true);
  }, []);

  // Clear search when route changes
  useEffect(() => {
    setSearchQuery('');
  }, [pathname, setSearchQuery]);

  const handleViewAllNotifications = () => {
    // Navigate to notifications page - will be handled by sidebar
    window.location.href = '/notifications';
  };

  const handleLogout = async () => {
    try {
      logout(); // This will clear tokens and redirect to login
      toast.success('Logged out successfully');
    } catch (error) {
      console.error('Logout error:', error);
      toast.error('Logout failed');
    }
  };

  return (
    <>
      <header className="flex items-center justify-between mb-8">
        {/* Search */}
        <div className="flex-1 max-w-lg">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground w-4 h-4" />
            <input
              type="text"
              placeholder={placeholder}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-card border border-border rounded-lg py-2.5 pl-10 pr-4 focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>
        </div>

        {/* User Actions */}
        <div className="flex items-center space-x-6">
          {/* Notifications Dropdown */}
          <NotificationDropdown 
            onViewAll={handleViewAllNotifications} 
            onClose={() => {}} // Will be handled by dropdown state
          />

          {/* User Profile */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <div className="flex items-center space-x-3 cursor-pointer">
                <Avatar className="w-10 h-10">
                  <AvatarImage src="https://lh3.googleusercontent.com/aida-public/AB6AXuBEDhjvZxwXBGeQrTHHTedlQ79iObGAO9gJwTQ8KWlbK9RK7w_oGWfYweHlOdA-SkeMRUNjamvXIBbeGnOz7cIKQHlOVgZf4vD1BQbLDWcHtQ4IP7kEyYBqQ8As-bHYN_27DUaszBl4TfFlkrXhB1snOrlaoi1Wh_O_w4188QMikFs5Fa9cMBbiP-9-Xfn2GJLb2mvPZcHhcj6nzXWlAv2vIcb47vCvXZ2Btu9aWElFUFNvzWD20Pj24e_ZXeZCW59AwTJmiEP4nEXt" />
                  <AvatarFallback>
                    {isClient && user?.username?.charAt(0).toUpperCase() || 'U'}
                  </AvatarFallback>
                </Avatar>
                <div suppressHydrationWarning>
                  <p className="font-semibold text-sm">
                    {isClient ? (user?.username || 'User') : 'User'}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {isClient ? (
                      `SafeTNet ${user?.role === 'SUPER_ADMIN' || user?.role === 'SUPER ADMIN' 
                        ? 'Admin' 
                        : user?.role === 'SUB_ADMIN' || user?.role === 'SUB ADMIN' 
                        ? 'Sub-Admin' 
                        : 'User'}`
                    ) : 'SafeTNet Admin'}
                  </p>
                </div>
                <ExpandMore className="text-muted-foreground w-4 h-4" />
              </div>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              <DropdownMenuItem 
                className="cursor-pointer"
                onClick={() => router.push('/profile')}
              >
                <Person className="w-4 h-4 mr-2" />
                Profile
              </DropdownMenuItem>
              <DropdownMenuItem
                className="cursor-pointer"
                onClick={() => router.push('/settings')}
              >
                <Settings className="w-4 h-4 mr-2" />
                Settings
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem className="cursor-pointer" onClick={handleLogout}>
                <Logout className="w-4 h-4 mr-2" />
                Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>

    </>
  );
}
