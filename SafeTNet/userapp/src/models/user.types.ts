export interface User {
  id: string;
  name: string;
  email: string;
  phone: string;
  role: string;
  avatar?: string;
  status: 'online' | 'offline';
  plan?: 'free' | 'premium';
}

export interface Alert {
  id: string;
  type: 'emergency' | 'geofence' | 'report' | 'notification';
  title: string;
  message: string;
  timestamp: Date;
  read: boolean;
  location?: {
    lat: number;
    lng: number;
  };
}

export interface Report {
  id: string;
  title: string;
  description: string;
  type: string;
  status: 'pending' | 'in_progress' | 'resolved';
  location: {
    lat: number;
    lng: number;
    address: string;
  };
  images: string[];
  createdAt: Date;
  userId: string;
}

export interface ChatMessage {
  id: string;
  userId: string;
  userName: string;
  message: string;
  timestamp: Date;
  isRead: boolean;
}

export interface Geofence {
  id: string;
  name: string;
  radius: number;
  center: {
    lat: number;
    lng: number;
  };
  isActive: boolean;
}


