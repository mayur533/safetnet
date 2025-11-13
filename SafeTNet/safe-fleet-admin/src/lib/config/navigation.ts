export interface NavigationItem {
  name: string;
  href: string;
  icon: string;
}

// Main Admin Navigation - Full system access
export const mainAdminNavigation: NavigationItem[] = [
  {
    name: 'Dashboard',
    href: '/',
    icon: 'dashboard',
  },
  {
    name: 'Organizations',
    href: '/organizations',
    icon: 'business',
  },
  {
    name: 'Sub-Admins',
    href: '/sub-admins',
    icon: 'supervisor_account',
  },
  {
    name: 'Users',
    href: '/users',
    icon: 'people',
  },
  {
    name: 'Geofences',
    href: '/geofences',
    icon: 'public',
  },
  {
    name: 'Promocodes',
    href: '/promocodes',
    icon: 'confirmation_number',
  },
  {
    name: 'Alerts',
    href: '/alerts',
    icon: 'notifications_active',
  },
  {
    name: 'Incidents',
    href: '/incidents',
    icon: 'report',
  },
  {
    name: 'Notifications',
    href: '/notifications',
    icon: 'notifications',
  },
  {
    name: 'Analytics',
    href: '/analytics',
    icon: 'assessment',
  },
];

// Sub-Admin Navigation - Limited regional access
export const subAdminNavigation: NavigationItem[] = [
  {
    name: 'Dashboard',
    href: '/sub-admin/dashboard',
    icon: 'dashboard',
  },
  {
    name: 'Geofences',
    href: '/sub-admin/geofences',
    icon: 'public',
  },
  {
    name: 'Security Officers',
    href: '/sub-admin/officers',
    icon: 'security',
  },
  {
    name: 'Notifications',
    href: '/sub-admin/notifications',
    icon: 'notifications',
  },
  {
    name: 'Incident Logs',
    href: '/sub-admin/incidents',
    icon: 'report',
  },
];

// Helper function to get navigation based on role
export function getNavigationByRole(role: string): NavigationItem[] {
  // Normalize role: convert to uppercase and replace underscores with spaces
  const normalizedRole = role.toUpperCase().replace(/_/g, ' ');
  
  // Check for admin roles (SUPER ADMIN, SUPER_ADMIN, ADMIN)
  if (normalizedRole === 'SUPER ADMIN' || normalizedRole === 'ADMIN') {
    return mainAdminNavigation;
  } 
  // Check for sub-admin roles (SUB ADMIN, SUB_ADMIN, SUBADMIN)
  else if (normalizedRole === 'SUB ADMIN' || normalizedRole === 'SUBADMIN') {
    return subAdminNavigation;
  }
  
  // Default to main admin navigation
  return mainAdminNavigation;
}

