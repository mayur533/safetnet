'use client';

import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Label } from '@/components/ui/label';
import { useSearch } from '@/lib/contexts/search-context';
import { TableLoading } from '@/components/ui/content-loading';
import { notificationsService, type Notification } from '@/lib/services/notifications';

const getStatusBadge = (notificationType: 'NORMAL' | 'EMERGENCY') => {
  if (notificationType === 'EMERGENCY') {
    return (
      <Badge className="bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300 border border-red-200">
        <span className="w-2 h-2 bg-red-500 rounded-full mr-2 animate-pulse"></span>
        Emergency
      </Badge>
    );
  }
  return (
    <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-300 border border-blue-200">
      <span className="w-2 h-2 bg-blue-500 rounded-full mr-2"></span>
      Normal
    </Badge>
  );
};

type SortField = 'created_at' | 'title' | 'notification_type';
type SortOrder = 'asc' | 'desc';
type FilterType = 'all' | 'NORMAL' | 'EMERGENCY' | 'unread';

export function NotificationsContainer() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [filter, setFilter] = useState<FilterType>('all');
  const { searchQuery } = useSearch();
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(10);
  const [sortField, setSortField] = useState<SortField>('created_at');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [showPaginationMenu, setShowPaginationMenu] = useState(false);
  const [showFilterMenu, setShowFilterMenu] = useState(false);
  const [showSortMenu, setShowSortMenu] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [viewDetailsNotification, setViewDetailsNotification] = useState<Notification | null>(null);
  const [deleteNotificationId, setDeleteNotificationId] = useState<number | null>(null);

  useEffect(() => {
    fetchNotifications();
  }, []);

  const fetchNotifications = async () => {
    try {
      setIsLoading(true);
      const data = await notificationsService.getAll();
      setNotifications(data);
    } catch (error: unknown) {
      console.error('Error fetching notifications:', error);
      toast.error('Failed to load notifications');
    } finally {
      setIsLoading(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleteNotificationId) return;
    
    try {
      await notificationsService.delete(deleteNotificationId);
      toast.success('Notification deleted successfully');
      setDeleteNotificationId(null);
      fetchNotifications(); // Refresh list
    } catch (error: unknown) {
      console.error('Delete error:', error);
      toast.error(error instanceof Error ? error.message : 'Failed to delete notification');
    }
  };

  const handleMarkAsRead = async (id: string) => {
    try {
      // Update local state immediately for instant feedback
      setNotifications(notifications.map(n => 
        n.id.toString() === id ? { ...n, is_read: true } : n
      ));
      
      // Mark as read in background
      await notificationsService.markAsRead(Number(id));
      
      // Refetch to sync with server
      fetchNotifications();
    } catch (error: unknown) {
      console.error('Error marking notification as read:', error);
      // Revert local state on error
      setNotifications(notifications.map(n => 
        n.id.toString() === id ? { ...n, is_read: false } : n
      ));
      toast.error('Failed to mark notification as read');
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  // Filter by type and read status
  let filteredNotifications = notifications;
  
  if (filter === 'unread') {
    filteredNotifications = filteredNotifications.filter(n => !n.is_read);
  } else if (filter === 'NORMAL' || filter === 'EMERGENCY') {
    filteredNotifications = filteredNotifications.filter(n => n.notification_type === filter);
  }

  // Filter by search query
  if (searchQuery) {
    filteredNotifications = filteredNotifications.filter(
      (notif) =>
        notif.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        notif.message.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }

  // Sort
  filteredNotifications = [...filteredNotifications].sort((a, b) => {
    const aValue = a[sortField as keyof Notification];
    const bValue = b[sortField as keyof Notification];

    // Handle created_at sorting differently
    if (sortField === 'created_at') {
      if (sortOrder === 'asc') {
        return new Date(aValue as string).getTime() - new Date(bValue as string).getTime();
      } else {
        return new Date(bValue as string).getTime() - new Date(aValue as string).getTime();
      }
    }

    // Handle string sorting
    if (sortOrder === 'asc') {
      return String(aValue || '').localeCompare(String(bValue || ''));
    } else {
      return String(bValue || '').localeCompare(String(aValue || ''));
    }
  });

  // Pagination
  const totalPages = Math.ceil(filteredNotifications.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedNotifications = filteredNotifications.slice(startIndex, endIndex);

  const unsentCount = notifications.filter(n => !n.is_sent).length;
  const emergencyCount = notifications.filter(n => n.notification_type === 'EMERGENCY').length;

  if (isLoading) {
    return (
      <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
        {/* Header Loading */}
        <div className="flex items-center justify-between mb-6 animate-pulse">
          <div>
            <div className="h-6 w-40 bg-muted rounded mb-2"></div>
            <div className="h-4 w-48 bg-muted/60 rounded"></div>
          </div>
        </div>

        {/* Controls Loading */}
        <div className="flex items-center justify-end gap-3 mb-6 animate-pulse">
          <div className="h-10 w-32 bg-muted rounded-lg"></div>
          <div className="h-10 w-24 bg-muted rounded-lg"></div>
          <div className="h-10 w-24 bg-muted rounded-lg"></div>
        </div>

        {/* Table Loading */}
        <TableLoading rows={itemsPerPage} columns={5} />

        {/* Pagination Info Loading */}
        <div className="mt-4 flex items-center justify-between animate-pulse">
          <div className="h-4 w-48 bg-muted rounded"></div>
          <div className="h-4 w-32 bg-muted rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="font-semibold text-lg">All Notifications</h3>
          <p className="text-sm text-muted-foreground">
            {notifications.length} total • {emergencyCount} emergency • {unsentCount} unsent
          </p>
        </div>
      </div>

      {/* Pagination, Filter, and Sort Controls */}
      <div className="flex items-center justify-end gap-3 mb-6">

        {/* Pagination Button */}
        <div className="relative">
          <button
            onClick={() => {
              setShowPaginationMenu(!showPaginationMenu);
              setShowFilterMenu(false);
              setShowSortMenu(false);
            }}
            className="flex items-center gap-2 px-4 py-2 bg-background border border-border rounded-lg hover:bg-muted transition-colors"
          >
            <span className="material-icons text-lg">apps</span>
            <span className="text-sm font-medium">Pagination</span>
          </button>

          {/* Pagination Dropdown */}
          {showPaginationMenu && (
            <div className="absolute right-0 mt-2 w-56 bg-card border border-border rounded-lg shadow-lg z-10">
              <div className="p-2">
                <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase">
                  Items per page
                </div>
                {[10, 25, 50, 100].map((count) => (
                  <button
                    key={count}
                    onClick={() => {
                      setItemsPerPage(count);
                      setCurrentPage(1);
                      setShowPaginationMenu(false);
                    }}
                    className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                      itemsPerPage === count
                        ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                        : 'hover:bg-muted'
                    }`}
                  >
                    {count} items
                  </button>
                ))}

              </div>
            </div>
          )}
        </div>

        {/* Filter Button */}
        <div className="relative">
          <button
            onClick={() => {
              setShowFilterMenu(!showFilterMenu);
              setShowPaginationMenu(false);
              setShowSortMenu(false);
            }}
            className="flex items-center gap-2 px-4 py-2 bg-background border border-border rounded-lg hover:bg-muted transition-colors"
          >
            <span className="material-icons text-lg">filter_list</span>
            <span className="text-sm font-medium">Filter</span>
            {filter !== 'all' && (
              <span className="w-2 h-2 bg-indigo-600 rounded-full"></span>
            )}
          </button>

          {/* Filter Dropdown */}
          {showFilterMenu && (
            <div className="absolute right-0 mt-2 w-56 bg-card border border-border rounded-lg shadow-lg z-10">
              <div className="p-2">
                <button
                  onClick={() => {
                    setFilter('all');
                    setCurrentPage(1);
                    setShowFilterMenu(false);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                    filter === 'all'
                      ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                      : 'hover:bg-muted'
                  }`}
                >
                  All
                </button>
                <button
                  onClick={() => {
                    setFilter('unread');
                    setCurrentPage(1);
                    setShowFilterMenu(false);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center gap-2 ${
                    filter === 'unread'
                      ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                      : 'hover:bg-muted'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-blue-500"></span>
                  Unread
                </button>
                <button
                  onClick={() => {
                    setFilter('NORMAL');
                    setCurrentPage(1);
                    setShowFilterMenu(false);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center gap-2 ${
                    filter === 'NORMAL'
                      ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                      : 'hover:bg-muted'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-blue-500"></span>
                  Normal
                </button>
                <button
                  onClick={() => {
                    setFilter('EMERGENCY');
                    setCurrentPage(1);
                    setShowFilterMenu(false);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center gap-2 ${
                    filter === 'EMERGENCY'
                      ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                      : 'hover:bg-muted'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
                  Emergency
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Sort Button */}
        <div className="relative">
          <button
            onClick={() => {
              setShowSortMenu(!showSortMenu);
              setShowPaginationMenu(false);
              setShowFilterMenu(false);
            }}
            className="flex items-center gap-2 px-4 py-2 bg-background border border-border rounded-lg hover:bg-muted transition-colors"
          >
            <span className="material-icons text-lg">sort</span>
            <span className="text-sm font-medium">Sort</span>
          </button>

          {/* Sort Dropdown */}
          {showSortMenu && (
            <div className="absolute right-0 mt-2 w-56 bg-card border border-border rounded-lg shadow-lg z-10">
              <div className="p-2">
                <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase">
                  Sort By
                </div>
                <button
                  onClick={() => {
                    if (sortField === 'created_at') {
                      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                    } else {
                      setSortField('created_at');
                      setSortOrder('desc');
                    }
                    setCurrentPage(1);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                    sortField === 'created_at'
                      ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                      : 'hover:bg-muted'
                  }`}
                >
                  <span>Date Created</span>
                  {sortField === 'created_at' && (
                    <span className="text-xs font-medium">{sortOrder === 'desc' ? 'Newest' : 'Oldest'}</span>
                  )}
                </button>
                <button
                  onClick={() => {
                    if (sortField === 'title') {
                      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                    } else {
                      setSortField('title');
                      setSortOrder('asc');
                    }
                    setCurrentPage(1);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                    sortField === 'title'
                      ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                      : 'hover:bg-muted'
                  }`}
                >
                  <span>Title</span>
                  {sortField === 'title' && (
                    <span className="text-xs font-medium">{sortOrder === 'asc' ? 'A-Z' : 'Z-A'}</span>
                  )}
                </button>
                <button
                  onClick={() => {
                    if (sortField === 'notification_type') {
                      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                    } else {
                      setSortField('notification_type');
                      setSortOrder('asc');
                    }
                    setCurrentPage(1);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                    sortField === 'notification_type'
                      ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                      : 'hover:bg-muted'
                  }`}
                >
                  <span>Type</span>
                  {sortField === 'notification_type' && (
                    <span className="text-xs font-medium">{sortOrder === 'asc' ? 'A-Z' : 'Z-A'}</span>
                  )}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
              <TableRow className="border-b">
                <TableHead className="text-muted-foreground text-sm font-medium w-3"></TableHead>
                <TableHead className="text-muted-foreground text-sm font-medium">Title</TableHead>
                <TableHead className="text-muted-foreground text-sm font-medium">Message</TableHead>
                <TableHead className="text-muted-foreground text-sm font-medium">Geofence</TableHead>
                <TableHead className="text-muted-foreground text-sm font-medium">Organization</TableHead>
                <TableHead className="text-muted-foreground text-sm font-medium">Type</TableHead>
                <TableHead className="text-muted-foreground text-sm font-medium text-right">Actions</TableHead>
              </TableRow>
          </TableHeader>
          <TableBody>
            {paginatedNotifications.map((notification) => (
              <TableRow
                key={notification.id}
                className={`border-b hover:bg-muted/50 transition-colors ${
                  !notification.is_read ? 'bg-blue-50/50 dark:bg-blue-950/20 cursor-pointer' : ''
                }`}
                onClick={() => {
                  if (!notification.is_read) {
                    handleMarkAsRead(notification.id.toString());
                  }
                }}
              >
                <TableCell className="py-4 px-2">
                  {!notification.is_read && (
                    <span className="w-2 h-2 bg-blue-600 rounded-full inline-block" title="Unread"></span>
                  )}
                </TableCell>
                <TableCell className="py-4 px-4">
                  <div>
                    <div className="font-medium text-sm">{notification.title}</div>
                    <div className="text-xs text-muted-foreground">By: {notification.created_by_username || 'System'}</div>
                  </div>
                </TableCell>
                <TableCell className="py-4 px-4">
                  <div className="text-sm max-w-xs truncate">{notification.message}</div>
                </TableCell>
                <TableCell className="py-4 px-4">
                  <div className="text-sm flex items-center gap-1">
                    <span className="material-icons text-xs text-indigo-600">location_on</span>
                    {notification.target_geofences_names && notification.target_geofences_names.length > 0
                      ? `${notification.target_geofences_names.map(g => g.name).join(', ')}`
                      : notification.target_geofence_name || 'All'
                    }
                  </div>
                </TableCell>
                <TableCell className="py-4 px-4">
                  <div className="text-sm flex items-center gap-1">
                    <span className="material-icons text-xs text-indigo-600">business</span>
                    {notification.organization_name || '-'}
                  </div>
                </TableCell>
                <TableCell className="py-4 px-4">
                  {getStatusBadge(notification.notification_type)}
                </TableCell>
                <TableCell className="py-4 px-4 text-right">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-8 w-8 p-0 hover:bg-muted"
                      >
                        <span className="material-icons text-lg">more_vert</span>
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-48">
                      <DropdownMenuItem 
                        className="cursor-pointer"
                        onClick={() => setViewDetailsNotification(notification)}
                      >
                        <span className="material-icons text-sm mr-2">visibility</span>
                        View Details
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        className="cursor-pointer text-red-600 focus:text-red-600"
                        onClick={() => setDeleteNotificationId(notification.id)}
                      >
                        <span className="material-icons text-sm mr-2">delete</span>
                        Delete
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Pagination Info */}
      <div className="mt-4 flex items-center justify-between text-sm text-muted-foreground">
        <p>
          Showing {startIndex + 1}-{Math.min(endIndex, filteredNotifications.length)} of {filteredNotifications.length} notifications
          {filter !== 'all' && (
            <span className="ml-2 text-indigo-600 font-medium">
              (Filtered: {filter})
            </span>
          )}
        </p>
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              if (currentPage > 1) {
                setCurrentPage(currentPage - 1);
              }
            }}
            disabled={currentPage === 1}
            className={`${currentPage === 1 ? 'opacity-50 cursor-not-allowed' : 'hover:text-foreground cursor-pointer'}`}
          >
            <span className="material-icons text-lg">chevron_left</span>
          </button>
          <button
            onClick={() => {
              if (currentPage < totalPages) {
                setCurrentPage(currentPage + 1);
              }
            }}
            disabled={currentPage === totalPages}
            className={`${currentPage === totalPages ? 'opacity-50 cursor-not-allowed' : 'hover:text-foreground cursor-pointer'}`}
          >
            <span className="material-icons text-lg">chevron_right</span>
          </button>
          <p>
            Page {currentPage} of {totalPages} • Sorted by: {sortField} ({sortOrder === 'asc' ? 'Asc' : 'Desc'})
          </p>
        </div>
      </div>

      {/* View Details Modal */}
      {viewDetailsNotification && (
        <Dialog open={!!viewDetailsNotification} onOpenChange={() => setViewDetailsNotification(null)}>
          <DialogContent className="sm:max-w-[700px] bg-card/95 backdrop-blur-xl border-border/50 p-4">
            <DialogHeader>
              <DialogTitle className="text-2xl font-bold flex items-center bg-gradient-to-r from-indigo-600 to-blue-600 bg-clip-text text-transparent">
                <span className="material-icons text-indigo-600 mr-2">
                  notifications_active
                </span>
                Notification Details
              </DialogTitle>
              <DialogDescription>
                Complete information about this notification
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3 mt-3">
              {/* Notification Header */}
              <div className="space-y-2 p-4 bg-gradient-to-r from-indigo-50 to-blue-50 dark:from-indigo-950/30 dark:to-blue-950/30 rounded-lg border border-indigo-200 dark:border-indigo-800">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold">{viewDetailsNotification.title}</h3>
                  {getStatusBadge(viewDetailsNotification.notification_type)}
                </div>
                <p className="text-sm text-muted-foreground">{viewDetailsNotification.message}</p>
              </div>

              {/* Notification Info Grid */}
              <div className="grid grid-cols-2 gap-4">
                {/* Type */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Notification Type</Label>
                  <div>{getStatusBadge(viewDetailsNotification.notification_type)}</div>
                </div>

                {/* Status */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Send Status</Label>
                  <div>
                    <Badge variant={viewDetailsNotification.is_sent ? "default" : "outline"}>
                      {viewDetailsNotification.is_sent ? 'Sent' : 'Draft'}
                    </Badge>
                  </div>
                </div>

                {/* Target Geofence */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Target Geofence</Label>
                  <p className="text-base font-medium flex items-center gap-1">
                    <span className="material-icons text-sm text-indigo-600">location_on</span>
                    {viewDetailsNotification.target_geofences_names && viewDetailsNotification.target_geofences_names.length > 0
                      ? `${viewDetailsNotification.target_geofences_names.map(g => g.name).join(', ')}`
                      : viewDetailsNotification.target_geofence_name || 'All Geofences'
                    }
                  </p>
                </div>

                {/* Organization */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Organization</Label>
                  <p className="text-base font-medium flex items-center gap-1">
                    <span className="material-icons text-sm text-indigo-600">business</span>
                    {viewDetailsNotification.organization_name || 'N/A'}
                  </p>
                </div>

                {/* Target Type */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Target Type</Label>
                  <p className="text-base font-medium">{viewDetailsNotification.target_type}</p>
                </div>

                {/* Created By */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Created By</Label>
                  <p className="text-base font-medium">{viewDetailsNotification.created_by_username || 'System'}</p>
                </div>

                {/* Created At */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Created</Label>
                  <p className="text-base font-medium">{formatDate(viewDetailsNotification.created_at)}</p>
                </div>

                {/* Sent At */}
                {viewDetailsNotification.sent_at && (
                  <div className="space-y-1">
                    <Label className="text-sm font-medium text-muted-foreground">Sent At</Label>
                    <p className="text-base font-medium">{formatDate(viewDetailsNotification.sent_at)}</p>
                  </div>
                )}
              </div>

              {/* Target Officers */}
              {viewDetailsNotification.target_officers && viewDetailsNotification.target_officers.length > 0 && (
                <div className="space-y-1 pt-2 border-t">
                  <Label className="text-sm font-medium text-muted-foreground">Target Officers</Label>
                  <div className="flex flex-wrap gap-2 mt-1">
                    {viewDetailsNotification.target_officers_names?.map((name, idx) => (
                      <Badge key={idx} variant="outline" className="text-xs">
                        {name}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Notification ID */}
              <div className="space-y-1 pt-2 border-t">
                <Label className="text-sm font-medium text-muted-foreground">Notification ID</Label>
                <p className="text-base font-mono text-sm">{viewDetailsNotification.id}</p>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex justify-end gap-3 pt-3 border-t mt-3">
              <Button
                variant="outline"
                onClick={() => setViewDetailsNotification(null)}
              >
                <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>close</span>
                Close
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      )}

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deleteNotificationId} onOpenChange={() => setDeleteNotificationId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <span className="material-icons text-red-600">warning</span>
              Delete Notification
            </AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this notification? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              className="bg-red-600 hover:bg-red-700 focus:ring-red-600"
            >
              <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>delete</span>
              Delete Notification
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
