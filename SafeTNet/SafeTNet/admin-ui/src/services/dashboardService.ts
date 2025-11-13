import api from './api';
import { DashboardKPIs } from '../types';

export const dashboardService = {
  // Get dashboard KPIs
  getKPIs: async (): Promise<DashboardKPIs> => {
    const response = await api.get('/auth/dashboard-kpis/');
    return response.data;
  },
};
