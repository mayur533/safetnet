import { API_ENDPOINTS, getAuthHeaders } from '@/lib/config/api';

export interface Report {
  id: number;
  report_type: string;
  title: string;
  description?: string;
  date_range_start: string;
  date_range_end: string;
  metrics: Record<string, unknown>;
  file_path?: string;
  generated_by_username: string;
  is_generated: boolean;
  generated_at?: string;
  created_at: string;
  updated_at: string;
}

export interface ReportCreateData {
  report_type: string;
  title: string;
  description?: string;
  date_range_start: string;
  date_range_end: string;
}

export const reportsService = {
  /**
   * Get all reports
   */
  async getAll(): Promise<Report[]> {
    const response = await fetch(API_ENDPOINTS.REPORTS.LIST, {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to fetch reports');
    }

    const data = await response.json();
    return data.results || data;
  },

  /**
   * Create/Generate a new report
   */
  async create(data: ReportCreateData): Promise<Report> {
    const response = await fetch(API_ENDPOINTS.REPORTS.CREATE, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(JSON.stringify(error));
    }

    return await response.json();
  },

  /**
   * Generate a report
   */
  async generate(data: ReportCreateData): Promise<Report> {
    const response = await fetch(API_ENDPOINTS.REPORTS.GENERATE, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(JSON.stringify(error));
    }

    return await response.json();
  },

  /**
   * Download a report
   */
  async download(id: number): Promise<Blob> {
    const response = await fetch(API_ENDPOINTS.REPORTS.DOWNLOAD(id), {
      method: 'GET',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to download report');
    }

    return await response.blob();
  },

  /**
   * Delete a report
   */
  async delete(id: number): Promise<void> {
    const response = await fetch(API_ENDPOINTS.REPORTS.DELETE(id), {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });

    if (!response.ok) {
      throw new Error('Failed to delete report');
    }
  },
};










