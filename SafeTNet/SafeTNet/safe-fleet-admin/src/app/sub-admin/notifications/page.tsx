'use client';

import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { ListLoading, FormLoading } from '@/components/ui/content-loading';
import { notificationsService, type Notification as BackendNotification } from '@/lib/services/notifications';
import { geofencesService, type Geofence } from '@/lib/services/geofences';
import { useSearch } from '@/lib/contexts/search-context';
import { LoadingDots } from '@/components/ui/loading-dots';

type NotificationType = 'NORMAL' | 'EMERGENCY';

export default function SubAdminNotificationsPage() {
  const { searchQuery } = useSearch();
  const [notifications, setNotifications] = useState<BackendNotification[]>([]);
  const [geofences, setGeofences] = useState<Geofence[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [notificationType, setNotificationType] = useState<NotificationType>('NORMAL');
  const [title, setTitle] = useState('');
  const [message, setMessage] = useState('');
  const [selectedGeofences, setSelectedGeofences] = useState<string[]>([]);
  const [selectionMode, setSelectionMode] = useState<'all' | 'select' | null>(null);

  // Fetch notifications and geofences on mount
  useEffect(() => {
    fetchNotifications();
    fetchGeofences();
  }, []);

  const fetchNotifications = async () => {
    try {
      const data = await notificationsService.getAll();
      setNotifications(data);
    } catch (error: unknown) {
      console.error('Failed to fetch notifications:', error);
      toast.error('Failed to load notifications');
    }
  };

  const fetchGeofences = async () => {
    try {
      setIsLoading(true);
      const data = await geofencesService.getAll();
      setGeofences(data);
    } catch (error: unknown) {
      console.error('Failed to fetch geofences:', error);
      toast.error('Failed to load geofences');
    } finally {
      setIsLoading(false);
    }
  };

  const handleGeofenceToggle = (geofenceId: string) => {
    setSelectedGeofences(prev => {
      if (prev.includes(geofenceId)) {
        return prev.filter(id => id !== geofenceId);
      } else {
        return [...prev, geofenceId];
      }
    });
  };

  const handleSendNotification = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!title || !message) {
      toast.error('Please fill in all required fields');
      return;
    }

    if (selectionMode === null) {
      toast.error('Please select geofence targeting mode');
      return;
    }

    // Determine which geofences to use
    const geofencesToUse = selectionMode === 'all' 
      ? geofences.map(g => g.id.toString())
      : selectedGeofences;

    if (selectionMode === 'select' && geofencesToUse.length === 0) {
      toast.error('Please select at least one geofence');
      return;
    }

    setIsSubmitting(true);

    try {
      // Send a single notification with all selected geofences
      const geofenceIds = geofencesToUse.map(id => parseInt(id));
      await notificationsService.send({
        notification_type: notificationType,
        title,
        message,
        target_type: 'GEOFENCE_OFFICERS',
        target_geofence_ids: geofenceIds,
      });

      const targetCount = selectionMode === 'all' ? geofences.length : selectedGeofences.length;
      toast.success(`${notificationType === 'EMERGENCY' ? 'Emergency' : 'Normal'} notification sent to ${targetCount} geofence(s)!`);
      
      // Reset form
      setTitle('');
      setMessage('');
      setSelectedGeofences([]);
      setSelectionMode(null);
      setNotificationType('NORMAL');
      
      // Refresh notifications list
      fetchNotifications();
    } catch (error: unknown) {
      console.error('Send notification error:', error);
      toast.error('Failed to send notification');
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold">Send Notifications</h1>
          <p className="text-muted-foreground mt-1">Send alerts to security officers in your area</p>
        </div>

        {/* Form Loading Skeleton */}
        <div className="bg-card p-6 rounded-lg shadow-md border">
          <FormLoading fields={4} />
        </div>

        {/* History Loading Skeleton */}
        <div className="bg-card rounded-lg shadow-md border">
          <div className="px-6 py-4 border-b">
            <div className="h-6 w-48 bg-muted rounded animate-pulse"></div>
          </div>
          <div className="p-6">
            <ListLoading rows={5} />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold">Send Notifications</h1>
        <p className="text-muted-foreground mt-1">Send alerts to security officers in your area</p>
      </div>

      {/* Notification Form */}
      <div className="bg-card p-6 rounded-lg shadow-md border">
        <form onSubmit={handleSendNotification} className="space-y-4">
          {/* Type Selection */}
          <div>
            <label className="block text-sm font-medium mb-2">Notification Type</label>
                <div className="grid grid-cols-2 gap-4">
                  <button
                    type="button"
                    onClick={() => setNotificationType('NORMAL')}
                    className={`p-4 rounded-lg border-2 transition-all ${
                      notificationType === 'NORMAL'
                        ? 'border-primary bg-primary/10'
                        : 'border-border hover:border-primary/50'
                    }`}
                  >
                    <span className="material-icons-outlined text-primary mb-2" style={{ fontSize: '32px' }}>
                      notifications
                    </span>
                    <div className="font-medium">Normal Alert</div>
                  </button>
                  <button
                    type="button"
                    onClick={() => setNotificationType('EMERGENCY')}
                    className={`p-4 rounded-lg border-2 transition-all ${
                      notificationType === 'EMERGENCY'
                        ? 'border-red-500 bg-red-50'
                        : 'border-border hover:border-red-300'
                    }`}
                  >
                    <span className="material-icons-outlined text-red-600 mb-2" style={{ fontSize: '32px' }}>
                      emergency
                    </span>
                    <div className="font-medium text-red-600">Emergency Alert</div>
                  </button>
                </div>
          </div>

          {/* Title */}
          <div>
            <label className="block text-sm font-medium mb-2">Title</label>
            <input
              type="text"
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Enter notification title..."
              className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>

          {/* Message */}
          <div>
            <label className="block text-sm font-medium mb-2">Message</label>
            <textarea
              required
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Enter your message..."
              rows={4}
              className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary resize-none"
            />
            <div className="text-xs text-muted-foreground mt-1">
              {message.length} / 500 characters
            </div>
          </div>

          {/* Target Geofences */}
          <div>
            <label className="block text-sm font-medium mb-3">Target Geofence(s) <span className="text-red-500">*</span></label>
            {geofences.length === 0 ? (
              <p className="text-sm text-muted-foreground">No geofences available</p>
            ) : (
              <>
                {/* Mode Selection Buttons */}
                <div className="grid grid-cols-2 gap-3 mb-3">
                  <button
                    type="button"
                    onClick={() => {
                      setSelectionMode('all');
                      setSelectedGeofences([]);
                    }}
                    className={`p-4 rounded-lg border-2 transition-all flex items-center justify-center space-x-2 ${
                      selectionMode === 'all'
                        ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-950/30'
                        : 'border-border hover:border-indigo-300'
                    }`}
                  >
                    <span className="material-icons text-xl">select_all</span>
                    <span className="font-medium">All Geofences</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectionMode('select');
                      setSelectedGeofences([]);
                    }}
                    className={`p-4 rounded-lg border-2 transition-all flex items-center justify-center space-x-2 ${
                      selectionMode === 'select'
                        ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-950/30'
                        : 'border-border hover:border-indigo-300'
                    }`}
                  >
                    <span className="material-icons text-xl">checklist</span>
                    <span className="font-medium">Select Specific</span>
                  </button>
                </div>

                {/* Show selection when "Select" mode is active */}
                {selectionMode === 'select' && (
                  <div className="max-h-60 overflow-y-auto border rounded-lg p-3 space-y-2">
                    {geofences.map((geofence) => (
                      <label
                        key={geofence.id}
                        className="flex items-center space-x-3 p-3 rounded-lg hover:bg-muted/50 cursor-pointer transition-colors"
                      >
                        <input
                          type="checkbox"
                          checked={selectedGeofences.includes(geofence.id.toString())}
                          onChange={() => handleGeofenceToggle(geofence.id.toString())}
                          className="w-4 h-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                        />
                        <span className="material-icons text-indigo-600 text-sm">location_on</span>
                        <span className="text-sm">{geofence.name}</span>
                        {geofence.organization_name && (
                          <span className="text-xs text-muted-foreground ml-auto">
                            ({geofence.organization_name})
                          </span>
                        )}
                      </label>
                    ))}
                  </div>
                )}

                {/* Status Message */}
                <p className="text-xs text-muted-foreground mt-2">
                  {selectionMode === 'all' && `${geofences.length} geofence(s) will receive the notification`}
                  {selectionMode === 'select' && `${selectedGeofences.length} geofence(s) selected`}
                  {selectionMode === null && 'Select how to target geofences'}
                </p>
              </>
            )}
          </div>

          {/* Submit Button */}
          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={isSubmitting}
              className={`px-6 py-2 rounded-lg text-white transition-colors flex items-center space-x-2 ${
                notificationType === 'EMERGENCY'
                  ? 'bg-red-600 hover:bg-red-700'
                  : 'bg-primary hover:bg-primary/90'
              } disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              {isSubmitting ? (
                <>
                  <LoadingDots />
                  <span>Sending</span>
                </>
              ) : (
                <>
                  <span className="material-icons-outlined">send</span>
                  <span>Send Notification</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Notification History */}
      <div className="bg-card rounded-lg shadow-md border">
        <div className="px-6 py-4 border-b">
          <h3 className="text-lg font-semibold">Notification History</h3>
        </div>
        <div className="divide-y">
          {(() => {
            // Filter notifications by search query
            const filteredNotifications = searchQuery
              ? notifications.filter((notification) => {
                  const query = searchQuery.toLowerCase();
                  // Check target_geofences_names for search
                  const geofencesMatch = notification.target_geofences_names 
                    ? notification.target_geofences_names.some(g => g.name.toLowerCase().includes(query))
                    : false;
                  return (
                    notification.title?.toLowerCase().includes(query) ||
                    notification.message?.toLowerCase().includes(query) ||
                    notification.notification_type?.toLowerCase().includes(query) ||
                    notification.target_type?.toLowerCase().includes(query) ||
                    notification.target_geofence?.toString().includes(query) ||
                    notification.target_geofence_name?.toLowerCase().includes(query) ||
                    geofencesMatch ||
                    notification.id.toString().includes(query)
                  );
                })
              : notifications;

            return filteredNotifications.length === 0 ? (
              <div className="p-12 text-center">
                <span className="material-icons text-6xl text-muted-foreground mb-2">
                  notifications_none
                </span>
                <p className="text-muted-foreground">
                  {searchQuery ? 'No matching notifications found' : 'No notifications yet'}
                </p>
              </div>
            ) : (
              filteredNotifications.map((notification) => (
              <div 
                key={notification.id} 
                className={`p-6 hover:bg-muted/30 transition-colors ${
                  !notification.is_read ? 'bg-blue-50/50 dark:bg-blue-950/20 border-l-4 border-blue-600' : ''
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-4 flex-1">
                    <div className={`p-3 rounded-lg ${
                      notification.notification_type === 'EMERGENCY' 
                        ? 'bg-red-100' 
                        : 'bg-blue-100'
                    }`}>
                      <span className={`material-icons-outlined ${
                        notification.notification_type === 'EMERGENCY' ? 'text-red-600' : 'text-blue-600'
                      }`} style={{ fontSize: '24px' }}>
                        {notification.notification_type === 'EMERGENCY' ? 'emergency' : 'notifications'}
                      </span>
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center space-x-2 mb-1">
                        {!notification.is_read && (
                          <span className="w-2 h-2 bg-blue-600 rounded-full flex-shrink-0" title="Unread"></span>
                        )}
                        <h4 className={`font-semibold ${!notification.is_read ? 'font-bold' : ''}`}>
                          {notification.title}
                        </h4>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${
                          notification.notification_type === 'EMERGENCY' 
                            ? 'bg-red-100 text-red-700' 
                            : 'bg-blue-100 text-blue-700'
                        }`}>
                          {notification.notification_type}
                        </span>
                        {notification.is_sent && (
                          <span className="text-xs px-2 py-0.5 rounded-full bg-green-100 text-green-700">
                            Sent
                          </span>
                        )}
                        {!notification.is_read && (
                          <span className="text-xs px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 border border-blue-300">
                            Unread
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground mb-2">{notification.message}</p>
                      <div className="flex items-center space-x-4 text-xs text-muted-foreground">
                        <span className="flex items-center space-x-1">
                          <span className="material-icons-outlined" style={{ fontSize: '14px' }}>location_on</span>
                          <span>
                            {notification.target_geofences_names && notification.target_geofences_names.length > 0
                              ? `${notification.target_geofences_names.map(g => g.name).join(', ')}`
                              : notification.target_geofence_name || 'All'
                            }
                          </span>
                        </span>
                        <span className="flex items-center space-x-1">
                          <span className="material-icons-outlined" style={{ fontSize: '14px' }}>category</span>
                          <span>{notification.target_type}</span>
                        </span>
                        <span className="flex items-center space-x-1">
                          <span className="material-icons-outlined" style={{ fontSize: '14px' }}>schedule</span>
                          <span>{new Date(notification.created_at).toLocaleString()}</span>
                        </span>
                      </div>
                    </div>
                  </div>
                  <button className="text-muted-foreground hover:text-foreground p-2">
                    <span className="material-icons-outlined">more_vert</span>
                  </button>
                </div>
              </div>
              ))
            );
          })()}
        </div>
      </div>
    </div>
  );
}
