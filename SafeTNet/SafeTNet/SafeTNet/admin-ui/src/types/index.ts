export interface User {
  id: number;
  username: string;
  email: string;
  role: 'SUPER_ADMIN' | 'SUB_ADMIN';
  is_active: boolean;
  date_joined: string;
}

export interface AuthTokens {
  access: string;
  refresh: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  password_confirm: string;
  role?: 'SUPER_ADMIN' | 'SUB_ADMIN';
}

export interface AuthResponse {
  access: string;
  refresh: string;
  user: User;
}

export interface ApiError {
  message: string;
  details?: Record<string, string[]>;
}

export interface PaginatedResponse<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

export interface Organization {
  id: number;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface Geofence {
  id: number;
  name: string;
  description: string;
  polygon_json: any;
  organization: number;
  organization_name: string;
  active: boolean;
  created_by_username: string;
  created_at: string;
  updated_at: string;
  center_point: [number, number] | null;
}

export interface GeofenceCreateRequest {
  name: string;
  description?: string;
  polygon_json: any;
  organization: number;
  active: boolean;
}

export interface GeofenceUpdateRequest {
  name: string;
  description?: string;
  active: boolean;
}

export interface UserListItem {
  id: number;
  username: string;
  email: string;
  first_name: string;
  last_name: string;
  role: 'SUPER_ADMIN' | 'SUB_ADMIN' | 'USER';
  organization: number | null;
  organization_name: string | null;
  is_active: boolean;
  date_joined: string;
  last_login: string | null;
}

export interface Alert {
  id: number;
  geofence: number | null;
  geofence_name: string | null;
  user: number | null;
  user_username: string | null;
  alert_type: 'GEOFENCE_ENTER' | 'GEOFENCE_EXIT' | 'GEOFENCE_VIOLATION' | 'SYSTEM_ERROR' | 'SECURITY_BREACH' | 'MAINTENANCE';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  description: string;
  metadata: any;
  is_resolved: boolean;
  resolved_at: string | null;
  resolved_by_username: string | null;
  created_at: string;
  updated_at: string;
}

export interface GlobalReport {
  id: number;
  report_type: 'GEOFENCE_ANALYTICS' | 'USER_ACTIVITY' | 'ALERT_SUMMARY' | 'SYSTEM_HEALTH' | 'CUSTOM';
  title: string;
  description: string;
  date_range_start: string;
  date_range_end: string;
  metrics: any;
  file_path: string | null;
  generated_by_username: string;
  is_generated: boolean;
  generated_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ReportCreateRequest {
  report_type: 'GEOFENCE_ANALYTICS' | 'USER_ACTIVITY' | 'ALERT_SUMMARY' | 'SYSTEM_HEALTH' | 'CUSTOM';
  title: string;
  description?: string;
  date_range_start: string;
  date_range_end: string;
}

export interface DashboardKPIs {
  active_geofences: number;
  alerts_today: number;
  active_sub_admins: number;
  total_users: number;
  critical_alerts: number;
  system_health: string;
}
