import React, { useState, useEffect } from 'react';
import { notificationService, geofenceService, officerService } from '../services/api';
import { Notification, Geofence, SecurityOfficer, NotificationSendData } from '../types';
import { Bell, Plus, Send, Users, MapPin, AlertCircle } from 'lucide-react';

const Notifications: React.FC = () => {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [geofences, setGeofences] = useState<Geofence[]>([]);
  const [officers, setOfficers] = useState<SecurityOfficer[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [sending, setSending] = useState(false);
  const [formData, setFormData] = useState<NotificationSendData>({
    notification_type: 'NORMAL',
    title: '',
    message: '',
    target_type: 'ALL_OFFICERS',
    target_geofence_id: undefined,
    target_officer_ids: []
  });

  const notificationTypes = [
    { value: 'NORMAL', label: 'Normal', description: 'Regular notification' },
    { value: 'EMERGENCY', label: 'Emergency', description: 'Urgent alert with siren tone' }
  ];

  const targetTypes = [
    { value: 'ALL_OFFICERS', label: 'All Officers', description: 'Send to all active officers' },
    { value: 'GEOFENCE_OFFICERS', label: 'Geofence Officers', description: 'Send to officers assigned to specific geofence' },
    { value: 'SPECIFIC_OFFICERS', label: 'Specific Officers', description: 'Send to selected officers' },
    { value: 'SUB_ADMIN', label: 'Sub Admin Only', description: 'Send to sub-admin only' }
  ];

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [notificationsResponse, geofencesResponse, officersResponse] = await Promise.all([
        notificationService.getNotifications(),
        geofenceService.getGeofences(),
        officerService.getOfficers()
      ]);
      setNotifications(notificationsResponse.results);
      setGeofences(geofencesResponse.results);
      setOfficers(officersResponse.results);
    } catch (err: any) {
      setError(err.message || 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Show confirmation dialog for Emergency notifications
    if (formData.notification_type === 'EMERGENCY') {
      const confirmed = window.confirm(
        '⚠️ EMERGENCY ALERT CONFIRMATION ⚠️\n\n' +
        'You are about to send an EMERGENCY notification that will:\n' +
        '• Override silent mode on all devices\n' +
        '• Play a siren tone alert\n' +
        '• Be sent to all target recipients immediately\n\n' +
        'Are you sure you want to proceed?'
      );
      
      if (!confirmed) {
        return;
      }
    }
    
    setSending(true);

    try {
      await notificationService.sendNotification(formData);
      setShowForm(false);
      setFormData({
        notification_type: 'NORMAL',
        title: '',
        message: '',
        target_type: 'ALL_OFFICERS',
        target_geofence_id: undefined,
        target_officer_ids: []
      });
      fetchData();
    } catch (err: any) {
      setError(err.message || 'Failed to send notification');
    } finally {
      setSending(false);
    }
  };

  const handleOfficerSelection = (officerId: number) => {
    setFormData(prev => ({
      ...prev,
      target_officer_ids: prev.target_officer_ids?.includes(officerId)
        ? prev.target_officer_ids.filter(id => id !== officerId)
        : [...(prev.target_officer_ids || []), officerId]
    }));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Notifications</h1>
          <p className="mt-1 text-sm text-gray-500">
            Send alerts and notifications to your security officers
          </p>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
        >
          <Plus className="h-4 w-4 mr-2" />
          Send Notification
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Error</h3>
              <p className="mt-1 text-sm text-red-700">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Notifications List */}
      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        <ul className="divide-y divide-gray-200">
          {notifications.map((notification) => (
            <li key={notification.id}>
              <div className="px-4 py-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <div className={`h-10 w-10 rounded-full flex items-center justify-center ${
                        notification.notification_type === 'EMERGENCY' 
                          ? 'bg-red-100' 
                          : 'bg-blue-100'
                      }`}>
                        {notification.notification_type === 'EMERGENCY' ? (
                          <AlertCircle className="h-5 w-5 text-red-600" />
                        ) : (
                          <Bell className="h-5 w-5 text-blue-600" />
                        )}
                      </div>
                    </div>
                    <div className="ml-4 flex-1">
                      <div className="flex items-center">
                        <h3 className="text-lg font-medium text-gray-900">{notification.title}</h3>
                        <span className={`ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          notification.notification_type === 'EMERGENCY'
                            ? 'bg-red-100 text-red-800'
                            : 'bg-blue-100 text-blue-800'
                        }`}>
                          {notification.notification_type}
                        </span>
                        <span className={`ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          notification.is_sent
                            ? 'bg-green-100 text-green-800'
                            : 'bg-yellow-100 text-yellow-800'
                        }`}>
                          {notification.is_sent ? 'Sent' : 'Pending'}
                        </span>
                      </div>
                      <p className="text-sm text-gray-500 mt-1">{notification.message}</p>
                      <div className="mt-2 flex items-center space-x-4 text-xs text-gray-400">
                        <div className="flex items-center">
                          <Users className="h-3 w-3 mr-1" />
                          {notification.target_officers_names.length} recipients
                        </div>
                        {notification.target_geofence_name && (
                          <div className="flex items-center">
                            <MapPin className="h-3 w-3 mr-1" />
                            {notification.target_geofence_name}
                          </div>
                        )}
                        <div>
                          {new Date(notification.created_at).toLocaleString()}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>

      {/* Form Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-11/12 max-w-md shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                Send Notification
              </h3>
              
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label htmlFor="notification_type" className="block text-sm font-medium text-gray-700">
                    Notification Type *
                  </label>
                  <select
                    id="notification_type"
                    required
                    value={formData.notification_type}
                    onChange={(e) => setFormData(prev => ({ ...prev, notification_type: e.target.value as 'NORMAL' | 'EMERGENCY' }))}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                  >
                    {notificationTypes.map((type) => (
                      <option key={type.value} value={type.value}>
                        {type.label} - {type.description}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="title" className="block text-sm font-medium text-gray-700">
                    Title *
                  </label>
                  <input
                    type="text"
                    id="title"
                    required
                    value={formData.title}
                    onChange={(e) => setFormData(prev => ({ ...prev, title: e.target.value }))}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                    placeholder="Enter notification title"
                  />
                </div>

                <div>
                  <label htmlFor="message" className="block text-sm font-medium text-gray-700">
                    Message *
                  </label>
                  <textarea
                    id="message"
                    required
                    rows={3}
                    value={formData.message}
                    onChange={(e) => setFormData(prev => ({ ...prev, message: e.target.value }))}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                    placeholder="Enter notification message"
                  />
                </div>

                <div>
                  <label htmlFor="target_type" className="block text-sm font-medium text-gray-700">
                    Target Audience *
                  </label>
                  <select
                    id="target_type"
                    required
                    value={formData.target_type}
                    onChange={(e) => setFormData(prev => ({ ...prev, target_type: e.target.value as any }))}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                  >
                    {targetTypes.map((type) => (
                      <option key={type.value} value={type.value}>
                        {type.label} - {type.description}
                      </option>
                    ))}
                  </select>
                </div>

                {formData.target_type === 'GEOFENCE_OFFICERS' && (
                  <div>
                    <label htmlFor="target_geofence_id" className="block text-sm font-medium text-gray-700">
                      Select Geofence *
                    </label>
                    <select
                      id="target_geofence_id"
                      required
                      value={formData.target_geofence_id || ''}
                      onChange={(e) => setFormData(prev => ({ ...prev, target_geofence_id: e.target.value ? Number(e.target.value) : undefined }))}
                      className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                    >
                      <option value="">Select geofence</option>
                      {geofences.map((geofence) => (
                        <option key={geofence.id} value={geofence.id}>
                          {geofence.name}
                        </option>
                      ))}
                    </select>
                  </div>
                )}

                {formData.target_type === 'SPECIFIC_OFFICERS' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Select Officers *
                    </label>
                    <div className="max-h-32 overflow-y-auto border border-gray-300 rounded-md p-2">
                      {officers.filter(o => o.is_active).map((officer) => (
                        <label key={officer.id} className="flex items-center">
                          <input
                            type="checkbox"
                            checked={formData.target_officer_ids?.includes(officer.id) || false}
                            onChange={() => handleOfficerSelection(officer.id)}
                            className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                          />
                          <span className="ml-2 text-sm text-gray-700">{officer.name}</span>
                        </label>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => {
                      setShowForm(false);
                      setFormData({
                        notification_type: 'NORMAL',
                        title: '',
                        message: '',
                        target_type: 'ALL_OFFICERS',
                        target_geofence_id: undefined,
                        target_officer_ids: []
                      });
                    }}
                    className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={sending}
                    className="inline-flex items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {sending ? (
                      <>
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                        Sending...
                      </>
                    ) : (
                      <>
                        <Send className="h-4 w-4 mr-2" />
                        Send Notification
                      </>
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Notifications;
