import {User, Alert, Report, ChatMessage, Geofence} from '../models/user.types';

export const mockUser: User = {
  id: '1',
  name: 'John Doe',
  email: 'john.doe@example.com',
  phone: '+1234567890',
  role: 'User',
  status: 'online',
  avatar: 'https://i.pravatar.cc/150?img=12',
  plan: 'free',
};

export const mockAlerts: Alert[] = [
  {
    id: '1',
    type: 'emergency',
    title: 'Emergency Alert',
    message: 'Emergency situation detected in your area',
    timestamp: new Date(Date.now() - 1000 * 60 * 15),
    read: false,
    location: {lat: 37.7749, lng: -122.4194},
  },
  {
    id: '2',
    type: 'geofence',
    title: 'Geofence Alert',
    message: 'You have entered a restricted area',
    timestamp: new Date(Date.now() - 1000 * 60 * 30),
    read: false,
  },
  {
    id: '3',
    type: 'report',
    title: 'New Report',
    message: 'A new report has been submitted',
    timestamp: new Date(Date.now() - 1000 * 60 * 60),
    read: true,
  },
  {
    id: '4',
    type: 'notification',
    title: 'System Update',
    message: 'System maintenance scheduled for tonight',
    timestamp: new Date(Date.now() - 1000 * 60 * 120),
    read: true,
  },
];

export const mockReports: Report[] = [
  {
    id: '1',
    title: 'Suspicious Activity',
    description: 'Noticed suspicious activity near the main gate',
    type: 'Security',
    status: 'pending',
    location: {
      lat: 37.7749,
      lng: -122.4194,
      address: '123 Main St, San Francisco, CA',
    },
    images: [],
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 2),
    userId: '1',
  },
  {
    id: '2',
    title: 'Damaged Property',
    description: 'Fence damage reported in sector 5',
    type: 'Maintenance',
    status: 'in_progress',
    location: {
      lat: 37.7849,
      lng: -122.4094,
      address: '456 Oak Ave, San Francisco, CA',
    },
    images: [],
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 5),
    userId: '1',
  },
  {
    id: '3',
    title: 'Noise Complaint',
    description: 'Excessive noise from construction site',
    type: 'Complaint',
    status: 'resolved',
    location: {
      lat: 37.7649,
      lng: -122.4294,
      address: '789 Pine St, San Francisco, CA',
    },
    images: [],
    createdAt: new Date(Date.now() - 1000 * 60 * 60 * 24),
    userId: '1',
  },
];

export const mockChatMessages: ChatMessage[] = [
  {
    id: '1',
    userId: '2',
    userName: 'Jane Smith',
    message: 'Hey, did you see the alert?',
    timestamp: new Date(Date.now() - 1000 * 60 * 10),
    isRead: false,
  },
  {
    id: '2',
    userId: '3',
    userName: 'Mike Johnson',
    message: 'Meeting scheduled for 3 PM',
    timestamp: new Date(Date.now() - 1000 * 60 * 30),
    isRead: false,
  },
  {
    id: '3',
    userId: '4',
    userName: 'Sarah Williams',
    message: 'Thanks for the update!',
    timestamp: new Date(Date.now() - 1000 * 60 * 60),
    isRead: true,
  },
];

export const mockGeofences: Geofence[] = [
  {
    id: '1',
    name: 'Downtown Area',
    radius: 500,
    center: {lat: 37.7749, lng: -122.4194},
    isActive: true,
  },
  {
    id: '2',
    name: 'University Campus',
    radius: 1000,
    center: {lat: 37.7849, lng: -122.4094},
    isActive: true,
  },
  {
    id: '3',
    name: 'Shopping Mall',
    radius: 300,
    center: {lat: 37.7649, lng: -122.4294},
    isActive: false,
  },
];

export const mockStats = {
  totalAlerts: 24,
  activeReports: 5,
  resolvedToday: 12,
  locationStatus: 'active',
};

export const mockDataService = {
  getUser: (): Promise<User> => Promise.resolve(mockUser),
  getAlerts: (): Promise<Alert[]> => Promise.resolve(mockAlerts),
  getReports: (): Promise<Report[]> => Promise.resolve(mockReports),
  getChatMessages: (): Promise<ChatMessage[]> => Promise.resolve(mockChatMessages),
  getGeofences: (): Promise<Geofence[]> => Promise.resolve(mockGeofences),
  getStats: () => Promise.resolve(mockStats),
};


