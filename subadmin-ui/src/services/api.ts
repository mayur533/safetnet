import axios, { AxiosResponse } from 'axios';
import { 
  AuthResponse, 
  User, 
  Geofence, 
  SecurityOfficer, 
  Incident, 
  Notification, 
  DashboardKPIs,
  NotificationSendData,
  ApiResponse 
} from '../types';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000/api';

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle token refresh
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      try {
        const refreshToken = localStorage.getItem('refresh_token');
        if (refreshToken) {
          const response = await axios.post(`${API_BASE_URL}/refresh/`, {
            refresh: refreshToken,
          });
          
          const { access } = response.data;
          localStorage.setItem('access_token', access);
          
          originalRequest.headers.Authorization = `Bearer ${access}`;
          return api(originalRequest);
        }
      } catch (refreshError) {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        window.location.href = '/login';
      }
    }
    
    return Promise.reject(error);
  }
);

export const authService = {
  login: async (username: string, password: string): Promise<AuthResponse> => {
    const response = await api.post('/login/', { username, password });
    return response.data;
  },

  logout: async (): Promise<void> => {
    const refreshToken = localStorage.getItem('refresh_token');
    if (refreshToken) {
      await api.post('/logout/', { refresh: refreshToken });
    }
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  },

  getProfile: async (): Promise<User> => {
    const response = await api.get('/profile/');
    return response.data;
  },
};

export const geofenceService = {
  getGeofences: async (): Promise<ApiResponse<Geofence>> => {
    const response = await api.get('/admin/geofences/');
    return response.data;
  },

  createGeofence: async (data: Partial<Geofence>): Promise<Geofence> => {
    const response = await api.post('/admin/geofences/', data);
    return response.data;
  },

  updateGeofence: async (id: number, data: Partial<Geofence>): Promise<Geofence> => {
    const response = await api.put(`/admin/geofences/${id}/`, data);
    return response.data;
  },

  deleteGeofence: async (id: number): Promise<void> => {
    await api.delete(`/admin/geofences/${id}/`);
  },
};

export const officerService = {
  getOfficers: async (): Promise<ApiResponse<SecurityOfficer>> => {
    const response = await api.get('/admin/officers/');
    return response.data;
  },

  createOfficer: async (data: Partial<SecurityOfficer>): Promise<SecurityOfficer> => {
    const response = await api.post('/admin/officers/', data);
    return response.data;
  },

  updateOfficer: async (id: number, data: Partial<SecurityOfficer>): Promise<SecurityOfficer> => {
    const response = await api.put(`/admin/officers/${id}/`, data);
    return response.data;
  },

  deleteOfficer: async (id: number): Promise<void> => {
    await api.delete(`/admin/officers/${id}/`);
  },
};

export const incidentService = {
  getIncidents: async (): Promise<ApiResponse<Incident>> => {
    const response = await api.get('/admin/incidents/');
    return response.data;
  },

  createIncident: async (data: Partial<Incident>): Promise<Incident> => {
    const response = await api.post('/admin/incidents/', data);
    return response.data;
  },

  updateIncident: async (id: number, data: Partial<Incident>): Promise<Incident> => {
    const response = await api.put(`/admin/incidents/${id}/`, data);
    return response.data;
  },

  resolveIncident: async (id: number): Promise<void> => {
    await api.post(`/admin/incidents/${id}/resolve/`);
  },
};

export const notificationService = {
  getNotifications: async (): Promise<ApiResponse<Notification>> => {
    const response = await api.get('/admin/notifications/');
    return response.data;
  },

  sendNotification: async (data: NotificationSendData): Promise<{ message: string; notification_id: number; target_count: number }> => {
    const response = await api.post('/subadmin/notifications/send/', data);
    return response.data;
  },
};

export const dashboardService = {
  getKPIs: async (): Promise<DashboardKPIs> => {
    const response = await api.get('/subadmin/dashboard-kpis/');
    return response.data;
  },
};

export default api;
