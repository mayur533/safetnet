'use client';

import { useState } from 'react';
import { cn } from '@/lib/utils';
import { usePathname } from 'next/navigation';
import Link from 'next/link';
import { NavigationItem } from '@/lib/config/navigation';
import { Security, Settings, Dashboard, Business, SupervisorAccount, People, Public, ConfirmationNumber, NotificationsActive, Report, Notifications, Assessment } from '@mui/icons-material';

interface SidebarProps {
  navigation: NavigationItem[];
  title?: string;
  subtitle?: string;
}

// Icon mapping from string names to MUI components
const iconMap: Record<string, React.ComponentType<{ className?: string; style?: React.CSSProperties }>> = {
  dashboard: Dashboard,
  business: Business,
  supervisor_account: SupervisorAccount,
  people: People,
  public: Public,
  confirmation_number: ConfirmationNumber,
  notifications_active: NotificationsActive,
  report: Report,
  notifications: Notifications,
  assessment: Assessment,
  security: Security,
  settings: Settings,
};

const getIcon = (iconName: string) => {
  const IconComponent = iconMap[iconName] || Security;
  return <IconComponent className="w-5 h-5" />;
};

export function Sidebar({ navigation, title = 'SafeTNet', subtitle = 'Admin Panel' }: SidebarProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const pathname = usePathname();

  const toggleSidebar = () => {
    setIsExpanded(!isExpanded);
  };

  return (
    <aside 
      className={cn(
        "bg-card border-r border-border flex flex-col py-6 transition-all duration-300 ease-in-out",
        isExpanded ? "w-64" : "w-20"
      )}
    >
      {/* Logo Section */}
      <div className="mb-10 px-4">
        <button
          onClick={toggleSidebar}
          className="flex items-center space-x-3 w-full p-2 rounded-lg hover:bg-muted/50 transition-colors"
        >
          <Security className="text-primary flex-shrink-0 w-9 h-9" />
          {isExpanded && (
            <div className="flex flex-col">
              <span className="text-xl font-bold text-primary">{title}</span>
              <span className="text-xs text-muted-foreground">{subtitle}</span>
            </div>
          )}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex flex-col space-y-2 px-4">
        {navigation.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                'flex items-center space-x-3 p-3 rounded-lg transition-colors',
                isActive
                  ? 'bg-primary/10 text-primary'
                  : 'text-muted-foreground hover:text-primary hover:bg-muted/50'
              )}
            >
              {getIcon(item.icon)}
              {isExpanded && (
                <span className="text-sm font-medium truncate">{item.name}</span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Settings */}
      <div className="mt-auto px-4">
        <Link
          href="/settings"
          className={cn(
            'flex items-center space-x-3 p-3 text-muted-foreground hover:text-primary hover:bg-muted/50 transition-colors rounded-lg'
          )}
        >
          <Settings className="w-5 h-5 flex-shrink-0" />
          {isExpanded && (
            <span className="text-sm font-medium">Settings</span>
          )}
        </Link>
      </div>
    </aside>
  );
}
