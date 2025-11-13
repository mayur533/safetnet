import api from './api';
import { GlobalReport, ReportCreateRequest, PaginatedResponse } from '../types';

export const reportService = {
  // Get paginated list of Reports
  getReports: async (params?: {
    page?: number;
    page_size?: number;
    search?: string;
    report_type?: string;
    is_generated?: boolean;
    ordering?: string;
  }): Promise<PaginatedResponse<GlobalReport>> => {
    const response = await api.get('/auth/admin/reports/', { params });
    return response.data;
  },

  // Get single Report by ID
  getReport: async (id: number): Promise<GlobalReport> => {
    const response = await api.get(`/auth/admin/reports/${id}/`);
    return response.data;
  },

  // Create new Report
  createReport: async (data: ReportCreateRequest): Promise<GlobalReport> => {
    const response = await api.post('/auth/admin/reports/', data);
    return response.data;
  },

  // Generate Report
  generateReport: async (data: ReportCreateRequest): Promise<{ message: string; report_id: number; metrics: any }> => {
    const response = await api.post('/auth/reports/generate/', data);
    return response.data;
  },

  // Download Report
  downloadReport: async (reportId: number): Promise<Blob> => {
    const response = await api.get(`/auth/reports/${reportId}/download/`, {
      responseType: 'blob'
    });
    return response.data;
  },

  // Update Report
  updateReport: async (id: number, data: Partial<GlobalReport>): Promise<GlobalReport> => {
    const response = await api.put(`/auth/admin/reports/${id}/`, data);
    return response.data;
  },

  // Delete Report
  deleteReport: async (id: number): Promise<void> => {
    await api.delete(`/auth/admin/reports/${id}/`);
  },
};
