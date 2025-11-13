/**
 * Role Conversion Utilities
 * Converts between frontend display format and backend API format
 */

// Frontend display format to Backend API format
export const convertRoleToAPI = (frontendRole: string): string => {
  const roleMap: Record<string, string> = {
    'Admin': 'SUPER_ADMIN',
    'Sub-Admin': 'SUB_ADMIN',
    'Security': 'USER',
    'Resident': 'USER',
    'User': 'USER',
  };

  return roleMap[frontendRole] || 'USER';
};

// Backend API format to Frontend display format
export const convertRoleFromAPI = (apiRole: string): string => {
  const roleMap: Record<string, string> = {
    'SUPER_ADMIN': 'Admin',
    'SUB_ADMIN': 'Sub-Admin',
    'USER': 'User',
  };

  return roleMap[apiRole] || apiRole;
};

// Get display label in capital letters
export const getRoleDisplayLabel = (role: string): string => {
  const labelMap: Record<string, string> = {
    'SUPER_ADMIN': 'SUPER ADMIN',
    'SUB_ADMIN': 'SUB ADMIN',
    'USER': 'USER',
  };

  return labelMap[role] || role;
};


























