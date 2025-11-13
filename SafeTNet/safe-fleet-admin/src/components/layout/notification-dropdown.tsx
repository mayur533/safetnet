'use client';

import { useState, useEffect } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu';
import { notificationsService, type Notification as ApiNotification } from '@/lib/services/notifications';
import { Notifications, NotificationsOff, Info, Warning, CheckCircle, Error } from '@mui/icons-material';

interface Notification {
  id: string;
  title: string;
  message: string;
  time: string;
  type: 'info' | 'warning' | 'success' | 'error';
  unread: boolean;
}

const getNotificationIcon = (type: Notification['type']) => {
  switch (type) {
    case 'error':
      return <Error className="w-4 h-4" />;
    case 'success':
      return <CheckCircle className="w-4 h-4" />;
    case 'warning':
      return <Warning className="w-4 h-4" />;
    case 'info':
    default:
      return <Info className="w-4 h-4" />;
  }
};

const getNotificationColor = (type: Notification['type']) => {
  switch (type) {
    case 'error':
      return 'text-red-600';
    case 'success':
      return 'text-green-600';
    case 'warning':
      return 'text-orange-600';
    case 'info':
    default:
      return 'text-blue-600';
  }
};

interface NotificationDropdownProps {
  onViewAll: () => void;
  onClose?: () => void;
}

export function NotificationDropdown({ onViewAll }: NotificationDropdownProps) {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchNotifications();
  }, []);

  const fetchNotifications = async () => {
    try {
      setLoading(true);
      const data = await notificationsService.getAll();
      
      // Convert API notifications to dropdown format
      // Show only recent 5, and show as unread if is_read is false or undefined
      const recentNotifs: Notification[] = data
        .slice(0, 5)
        .map((notif: ApiNotification) => {
          // Check if read_users array exists and has length
          const isRead = notif.is_read === false ? false : (notif.is_read === true ? true : (notif.read_users && notif.read_users.length > 0));
          
          return {
            id: notif.id.toString(),
            title: notif.title,
            message: notif.message,
            time: new Date(notif.created_at).toLocaleDateString('en-US', {
              month: 'short',
              day: 'numeric',
              hour: '2-digit',
              minute: '2-digit',
            }),
            type: notif.notification_type === 'EMERGENCY' ? 'error' : 'info',
            unread: !isRead, // Unread if not marked as read
          };
        });

      setNotifications(recentNotifs);
    } catch (error) {
      console.error('Error fetching notifications:', error);
      // Keep empty array on error
    } finally {
      setLoading(false);
    }
  };

  const unreadCount = notifications.filter(n => n.unread).length;

  const handleViewAll = () => {
    onViewAll();
    setOpen(false);
  };

  const handleMarkAsRead = async (id: string) => {
    try {
      // Update local state immediately for instant feedback
      setNotifications(notifications.map(n => 
        n.id === id ? { ...n, unread: false } : n
      ));
      
      // Mark as read in background
      notificationsService.markAsRead(Number(id)).then(() => {
        // Only refetch if successful
        fetchNotifications();
      }).catch(error => {
        console.error('Error marking notification as read:', error);
        // Revert local state on error
        setNotifications(notifications.map(n => 
          n.id === id ? { ...n, unread: true } : n
        ));
      });
    } catch (error) {
      console.error('Error marking notification as read:', error);
    }
  };

  const handleMarkAllAsRead = async () => {
    try {
      // Update local state immediately for instant feedback
      setNotifications(notifications.map(n => ({ ...n, unread: false })));
      
      // Mark all as read in background
      const unreadNotifs = notifications.filter(n => n.unread);
      Promise.all(
        unreadNotifs.map(n => notificationsService.markAsRead(Number(n.id)))
      ).then(() => {
        // Only refetch if successful
        fetchNotifications();
      }).catch(error => {
        console.error('Error marking all as read:', error);
        // Revert to previous state on error
        fetchNotifications();
      });
    } catch (error) {
      console.error('Error marking all as read:', error);
    }
  };

  return (
    <DropdownMenu open={open} onOpenChange={setOpen}>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" className="relative text-muted-foreground hover:text-foreground">
          <Notifications className="w-5 h-5" />
          {unreadCount > 0 && (
            <Badge className="absolute -top-1 -right-1 w-5 h-5 p-0 bg-red-500 text-white text-xs flex items-center justify-center">
              {unreadCount}
            </Badge>
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-96">
        <div className="p-4 border-b flex items-center justify-between">
          <div>
            <h3 className="font-semibold text-sm">Notifications</h3>
            <p className="text-xs text-muted-foreground">{unreadCount} unread</p>
          </div>
          {unreadCount > 0 && (
            <Button
              variant="ghost"
              size="sm"
              onClick={handleMarkAllAsRead}
              className="text-xs h-7"
            >
              Mark all read
            </Button>
          )}
        </div>
        
        <div className="max-h-64 overflow-y-auto">
          {loading ? (
            <div className="p-8 text-center">
              <div className="animate-pulse text-muted-foreground">Loading...</div>
            </div>
          ) : notifications.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground">
              <NotificationsOff className="w-10 h-10 mb-2" />
              <p className="text-sm">No notifications</p>
            </div>
          ) : (
            notifications.slice(0, 4).map((notification) => (
              <div
                key={notification.id}
                onClick={() => {
                  if (notification.unread) {
                    handleMarkAsRead(notification.id);
                  }
                }}
                className={`p-3 hover:bg-muted/50 transition-colors border-b last:border-b-0 cursor-pointer ${
                  notification.unread ? 'bg-blue-50/50 dark:bg-blue-900/10' : ''
                }`}
              >
                <div className="flex items-start space-x-3">
                  <div className={`mt-0.5 ${getNotificationColor(notification.type)}`}>
                    {getNotificationIcon(notification.type)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">{notification.title}</p>
                    <p className="text-xs text-muted-foreground line-clamp-2">{notification.message}</p>
                    <p className="text-xs text-muted-foreground mt-1">{notification.time}</p>
                  </div>
                  {notification.unread && (
                    <div className="w-2 h-2 bg-blue-500 rounded-full mt-2 flex-shrink-0"></div>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
        
        <DropdownMenuSeparator />
        <div className="p-2">
          <Button
            variant="ghost"
            size="sm"
            className="w-full justify-center"
            onClick={handleViewAll}
          >
            View All Notifications
          </Button>
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
