export interface User {
  id: number;
  username: string;
  email: string;
  role: 'SUPER_ADMIN' | 'SUB_ADMIN' | 'USER';
  is_active: boolean;
  date_joined: string;
  organization?: Organization;
}

export interface Organization {
  id: number;
  name: string;
  description?: string;
  created_at: string;
  updated_at: string;
}

export interface Geofence {
  id: number;
  name: string;
  description?: string;
  polygon_json: any;
  organization: number;
  organization_name: string;
  active: boolean;
  created_by_username: string;
  created_at: string;
  updated_at: string;
  center_point?: [number, number];
}

export interface SecurityOfficer {
  id: number;
  name: string;
  contact: string;
  email?: string;
  assigned_geofence?: number;
  assigned_geofence_name?: string;
  organization: number;
  organization_name: string;
  is_active: boolean;
  created_by_username: string;
  created_at: string;
  updated_at: string;
}

export interface Incident {
  id: number;
  geofence: number;
  geofence_name: string;
  officer?: number;
  officer_name?: string;
  incident_type: 'SECURITY_BREACH' | 'UNAUTHORIZED_ACCESS' | 'SUSPICIOUS_ACTIVITY' | 'EMERGENCY' | 'MAINTENANCE' | 'OTHER';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  details: string;
  location: any;
  is_resolved: boolean;
  resolved_at?: string;
  resolved_by_username?: string;
  created_at: string;
  updated_at: string;
}

export interface Notification {
  id: number;
  notification_type: 'NORMAL' | 'EMERGENCY';
  title: string;
  message: string;
  target_type: 'ALL_OFFICERS' | 'GEOFENCE_OFFICERS' | 'SPECIFIC_OFFICERS' | 'SUB_ADMIN';
  target_geofence?: number;
  target_geofence_name?: string;
  target_officers: number[];
  target_officers_names: string[];
  organization: number;
  organization_name: string;
  is_sent: boolean;
  sent_at?: string;
  created_by_username: string;
  created_at: string;
  updated_at: string;
}

export interface AuthResponse {
  access: string;
  refresh: string;
  user: User;
}

export interface DashboardKPIs {
  active_geofences: number;
  total_officers: number;
  active_officers: number;
  incidents_today: number;
  unresolved_incidents: number;
  critical_incidents: number;
  notifications_sent_today: number;
  organization_name: string;
}

export interface NotificationSendData {
  notification_type: 'NORMAL' | 'EMERGENCY';
  title: string;
  message: string;
  target_type: 'ALL_OFFICERS' | 'GEOFENCE_OFFICERS' | 'SPECIFIC_OFFICERS' | 'SUB_ADMIN';
  target_geofence_id?: number;
  target_officer_ids?: number[];
}

export interface ApiResponse<T> {
  count: number;
  next?: string;
  previous?: string;
  results: T[];
}

export interface MapCoordinates {
  lat: number;
  lng: number;
}

export interface PolygonData {
  type: 'Polygon';
  coordinates: number[][][];
}
