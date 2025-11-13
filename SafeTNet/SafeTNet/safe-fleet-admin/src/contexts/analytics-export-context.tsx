'use client';

import React, { createContext, useContext, useState, useCallback } from 'react';
import { AnalyticsData } from '@/lib/services/analytics';
import { exportToPDF, exportToCSV, ExportData } from '@/lib/utils/export-utils';

interface AnalyticsExportContextType {
  setAnalyticsData: (data: AnalyticsData) => void;
  setAlertTypesData: (data: Array<{ name: string; value: number }>) => void;
  setUserRolesData: (data: Array<{ name: string; value: number }>) => void;
  setIncidentsTrendsData: (data: Array<{ month: string; resolved: number; unresolved: number }>) => void;
  handleExportPDF: () => Promise<void>;
  handleExportCSV: () => Promise<void>;
}

const AnalyticsExportContext = createContext<AnalyticsExportContextType | undefined>(undefined);

export function AnalyticsExportProvider({ children }: { children: React.ReactNode }) {
  const [analyticsData, setAnalyticsDataState] = useState<AnalyticsData | null>(null);
  const [alertTypesData, setAlertTypesDataState] = useState<Array<{ name: string; value: number }>>([]);
  const [userRolesData, setUserRolesDataState] = useState<Array<{ name: string; value: number }>>([]);
  const [incidentsTrendsData, setIncidentsTrendsDataState] = useState<Array<{ month: string; resolved: number; unresolved: number }>>([]);

  const setAnalyticsData = useCallback((data: AnalyticsData) => {
    setAnalyticsDataState(data);
  }, []);

  const setAlertTypesData = useCallback((data: Array<{ name: string; value: number }>) => {
    setAlertTypesDataState(data);
  }, []);

  const setUserRolesData = useCallback((data: Array<{ name: string; value: number }>) => {
    setUserRolesDataState(data);
  }, []);

  const setIncidentsTrendsData = useCallback((data: Array<{ month: string; resolved: number; unresolved: number }>) => {
    setIncidentsTrendsDataState(data);
  }, []);

  const handleExportPDF = useCallback(async () => {
    if (!analyticsData) {
      alert('No analytics data available for export');
      return;
    }

    try {
      const exportData: ExportData = {
        analytics: analyticsData,
        alertTypes: alertTypesData,
        userRoles: userRolesData,
        incidentsTrends: incidentsTrendsData,
      };

      await exportToPDF(exportData);
    } catch (error) {
      console.error('Error exporting to PDF:', error);
      alert('Failed to export PDF');
    }
  }, [analyticsData, alertTypesData, userRolesData, incidentsTrendsData]);

  const handleExportCSV = useCallback(async () => {
    if (!analyticsData) {
      alert('No analytics data available for export');
      return;
    }

    try {
      const exportData: ExportData = {
        analytics: analyticsData,
        alertTypes: alertTypesData,
        userRoles: userRolesData,
        incidentsTrends: incidentsTrendsData,
      };

      await exportToCSV(exportData);
    } catch (error) {
      console.error('Error exporting to CSV:', error);
      alert('Failed to export CSV');
    }
  }, [analyticsData, alertTypesData, userRolesData, incidentsTrendsData]);

  return (
    <AnalyticsExportContext.Provider
      value={{
        setAnalyticsData,
        setAlertTypesData,
        setUserRolesData,
        setIncidentsTrendsData,
        handleExportPDF,
        handleExportCSV,
      }}
    >
      {children}
    </AnalyticsExportContext.Provider>
  );
}

export function useAnalyticsExport() {
  const context = useContext(AnalyticsExportContext);
  if (!context) {
    throw new Error('useAnalyticsExport must be used within AnalyticsExportProvider');
  }
  return context;
}

