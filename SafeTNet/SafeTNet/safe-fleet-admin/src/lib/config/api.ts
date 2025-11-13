/**
 * API Configuration
 * Central configuration for all API endpoints and settings
 */

// Backend API Base URL
export const API_CONFIG = {
  BASE_URL: process.env.NEXT_PUBLIC_API_URL || 'https://safetnet-backend.onrender.com',
  AUTH_BASE_URL: process.env.NEXT_PUBLIC_API_URL 
    ? `${process.env.NEXT_PUBLIC_API_URL}/api/auth` 
    : 'https://safetnet-backend.onrender.com/api/auth',
  TIMEOUT: 30000, // 30 seconds
};

// API Endpoints
export const API_ENDPOINTS = {
  // Authentication
  AUTH: {
    LOGIN: `${API_CONFIG.AUTH_BASE_URL}/login/`,
    REGISTER: `${API_CONFIG.AUTH_BASE_URL}/register/`,
    LOGOUT: `${API_CONFIG.AUTH_BASE_URL}/logout/`,
    REFRESH: `${API_CONFIG.AUTH_BASE_URL}/refresh/`,
    PROFILE: `${API_CONFIG.AUTH_BASE_URL}/profile/`,
    REQUEST_RESET: `${API_CONFIG.AUTH_BASE_URL}/request-password-reset/`,
    RESET_PASSWORD: `${API_CONFIG.AUTH_BASE_URL}/reset-password/`,
  },
  
  // Organizations (Super Admin only)
  ORGANIZATIONS: {
    LIST: `${API_CONFIG.BASE_URL}/api/auth/admin/organizations/`,
    CREATE: `${API_CONFIG.BASE_URL}/api/auth/admin/organizations/`,
    DETAIL: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/organizations/${id}/`,
    UPDATE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/organizations/${id}/`,
    DELETE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/organizations/${id}/`,
  },
  
  // Sub-Admins (Super Admin only)
  SUB_ADMINS: {
    LIST: `${API_CONFIG.BASE_URL}/api/auth/admin/subadmins/`,
    CREATE: `${API_CONFIG.BASE_URL}/api/auth/admin/subadmins/`,
    DETAIL: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/subadmins/${id}/`,
    UPDATE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/subadmins/${id}/`,
    DELETE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/subadmins/${id}/`,
  },
  
  // Geofences
  GEOFENCES: {
    LIST: `${API_CONFIG.BASE_URL}/api/auth/admin/geofences/`,
    CREATE: `${API_CONFIG.BASE_URL}/api/auth/admin/geofences/`,
    DETAIL: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/geofences/${id}/`,
    UPDATE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/geofences/${id}/`,
    DELETE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/geofences/${id}/`,
  },
  
  // Alerts
  ALERTS: {
    LIST: `${API_CONFIG.BASE_URL}/api/auth/admin/alerts/`,
    CREATE: `${API_CONFIG.BASE_URL}/api/auth/admin/alerts/`,
    DETAIL: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/alerts/${id}/`,
    UPDATE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/alerts/${id}/`,
    RESOLVE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/alerts/${id}/`,
    DELETE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/alerts/${id}/`,
  },
  
  // Reports (Super Admin only)
  REPORTS: {
    LIST: `${API_CONFIG.BASE_URL}/api/auth/admin/reports/`,
    CREATE: `${API_CONFIG.BASE_URL}/api/auth/admin/reports/`,
    GENERATE: `${API_CONFIG.BASE_URL}/api/auth/reports/generate/`,
    DOWNLOAD: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/reports/${id}/download/`,
    DELETE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/reports/${id}/`,
  },
  
  // Dashboard
  DASHBOARD: {
    KPIS: `${API_CONFIG.BASE_URL}/api/auth/dashboard-kpis/`,
  },
  
  // Analytics
  ANALYTICS: {
    DATA: `${API_CONFIG.BASE_URL}/api/auth/analytics/data/`,
  },
  
  // Users
  USERS: {
    LIST: `${API_CONFIG.BASE_URL}/api/auth/admin/users/`,
    DETAIL: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/users/${id}/`,
    UPDATE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/users/${id}/`,
    DELETE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/users/${id}/`,
  },
  
  // Promocodes (Admin only)
  PROMOCODES: {
    LIST: `${API_CONFIG.BASE_URL}/api/auth/admin/promocode/`,
    CREATE: `${API_CONFIG.BASE_URL}/api/auth/admin/promocode/`,
    DETAIL: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/promocode/${id}/`,
    UPDATE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/promocode/${id}/`,
    DELETE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/promocode/${id}/`,
  },
  
  // Security Officers (Sub-Admin)
  OFFICERS: {
    LIST: `${API_CONFIG.BASE_URL}/api/auth/admin/officers/`,
    CREATE: `${API_CONFIG.BASE_URL}/api/auth/admin/officers/`,
    DETAIL: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/officers/${id}/`,
    UPDATE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/officers/${id}/`,
    DELETE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/officers/${id}/`,
  },
  
  // Incidents (Sub-Admin)
  INCIDENTS: {
    LIST: `${API_CONFIG.BASE_URL}/api/auth/admin/incidents/`,
    CREATE: `${API_CONFIG.BASE_URL}/api/auth/admin/incidents/`,
    DETAIL: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/incidents/${id}/`,
    UPDATE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/incidents/${id}/`,
    DELETE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/incidents/${id}/`,
    RESOLVE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/incidents/${id}/resolve/`,
  },
  
  // Notifications (Sub-Admin)
  NOTIFICATIONS: {
    LIST: `${API_CONFIG.BASE_URL}/api/auth/admin/notifications/`,
    CREATE: `${API_CONFIG.BASE_URL}/api/auth/admin/notifications/`,
    SEND: `${API_CONFIG.BASE_URL}/api/auth/subadmin/notifications/send/`,
    DETAIL: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/notifications/${id}/`,
    MARK_READ: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/notifications/${id}/mark-read/`,
    DELETE: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/notifications/${id}/`,
  },
  
  // Discount Emails (Admin)
  DISCOUNT_EMAILS: {
    LIST: `${API_CONFIG.BASE_URL}/api/auth/admin/discount-emails/`,
    CREATE: `${API_CONFIG.BASE_URL}/api/auth/admin/discount-emails/`,
    DETAIL: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/discount-emails/${id}/`,
  },
  
  // User Replies (Read-only)
  USER_REPLIES: {
    LIST: `${API_CONFIG.BASE_URL}/api/auth/admin/user-replies/`,
    DETAIL: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/user-replies/${id}/`,
  },
  
  // User Details (Read-only)
  USER_DETAILS: {
    LIST: `${API_CONFIG.BASE_URL}/api/auth/admin/user-details/`,
    DETAIL: (id: number) => `${API_CONFIG.BASE_URL}/api/auth/admin/user-details/${id}/`,
  },
  
  // Sub-Admin Dashboard
  SUBADMIN: {
    DASHBOARD_KPIS: `${API_CONFIG.BASE_URL}/api/auth/subadmin/dashboard-kpis/`,
  },
  
  // Documentation
  DOCS: {
    SCHEMA: `${API_CONFIG.BASE_URL}/api/schema/`,
    SWAGGER: `${API_CONFIG.BASE_URL}/api/docs/`,
    REDOC: `${API_CONFIG.BASE_URL}/api/redoc/`,
  },
};

// Storage Keys
export const STORAGE_KEYS = {
  ACCESS_TOKEN: 'access_token',
  REFRESH_TOKEN: 'refresh_token',
  USER: 'user',
};

// Default Headers
export const DEFAULT_HEADERS = {
  'Content-Type': 'application/json',
  'Accept': 'application/json',
};

// Export utility function to get auth headers
export const getAuthHeaders = (token?: string): HeadersInit => {
  // Check both localStorage and sessionStorage for the token (supports "Remember Me" functionality)
  let accessToken = token;
  if (!accessToken && typeof window !== 'undefined') {
    accessToken = localStorage.getItem(STORAGE_KEYS.ACCESS_TOKEN) || sessionStorage.getItem(STORAGE_KEYS.ACCESS_TOKEN) || undefined;
  }
  
  return {
    ...DEFAULT_HEADERS,
    ...(accessToken ? { 'Authorization': `Bearer ${accessToken}` } : {}),
  };
};


