'use client';

import { useState, useEffect } from 'react';
import { AnalyticsStats } from '@/components/analytics/analytics-stats';
import { AlertTrendsChart } from '@/components/analytics/alert-trends-chart';
import { AlertTypesChart } from '@/components/analytics/alert-types-chart';
import { UserActivityChart } from '@/components/analytics/user-activity-chart';
import { IncidentsChart } from '@/components/analytics/incidents-chart';
import { UserRolesChart } from '@/components/analytics/user-roles-chart';
import { RecentLogsTable } from '@/components/analytics/recent-logs-table';
import { DateRangeFilter } from '@/components/analytics/date-range-filter';
import { Button } from '@/components/ui/button';
import { CardLoading } from '@/components/ui/content-loading';
import { analyticsService, AnalyticsData } from '@/lib/services/analytics';
import { exportToPDF, exportToCSV, ExportData } from '@/lib/utils/export-utils';
import { alertsService } from '@/lib/services/alerts';
import { incidentsService } from '@/lib/services/incidents';
import { usersService } from '@/lib/services/users';
import { geofencesService } from '@/lib/services/geofences';
import { toast } from 'sonner';

export default function AnalyticsPage() {
  const [dateRange, setDateRange] = useState<{ from: Date; to: Date }>({
    from: new Date(new Date().setDate(new Date().getDate() - 30)),
    to: new Date(),
  });
  const [isLoading, setIsLoading] = useState(true);
  const [analyticsData, setAnalyticsData] = useState<AnalyticsData | null>(null);

  useEffect(() => {
    fetchAnalyticsData();
  }, []);

  const fetchAnalyticsData = async () => {
    try {
      setIsLoading(true);
      const data = await analyticsService.getAnalytics();
      setAnalyticsData(data);
    } catch (error) {
      console.error('Error fetching analytics:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleExportPDF = async () => {
    if (!analyticsData) {
      toast.error('No analytics data available');
      return;
    }

    try {
      toast.loading('Preparing PDF export...', { id: 'export-pdf' });
      
      // Fetch all detailed data
      const [allAlerts, allIncidents, allUsers, allGeofences] = await Promise.all([
        alertsService.getAll().catch(() => []),
        incidentsService.getAll().catch(() => []),
        usersService.getAll().catch(() => []),
        geofencesService.getAll().catch(() => []),
      ]);

      // Process alert types
      const alertTypesMap = new Map<string, number>();
      allAlerts.forEach(alert => {
        const type = alert.alert_type || 'Unknown';
        alertTypesMap.set(type, (alertTypesMap.get(type) || 0) + 1);
      });
      const alertTypes = Array.from(alertTypesMap.entries()).map(([name, value]) => ({ name, value }));

      // Process user roles
      const userRolesMap = new Map<string, number>();
      allUsers.forEach(user => {
        const role = user.role || 'Unknown';
        userRolesMap.set(role, (userRolesMap.get(role) || 0) + 1);
      });
      const userRoles = Array.from(userRolesMap.entries()).map(([name, value]) => ({ name, value }));

      // Process incidents trends (monthly)
      const incidentsTrendsMap = new Map<string, { resolved: number; unresolved: number }>();
      allIncidents.forEach(incident => {
        const date = new Date(incident.created_at);
        const monthKey = date.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
        const entry = incidentsTrendsMap.get(monthKey) || { resolved: 0, unresolved: 0 };
        if (incident.is_resolved) entry.resolved++;
        else entry.unresolved++;
        incidentsTrendsMap.set(monthKey, entry);
      });
      const incidentsTrends = Array.from(incidentsTrendsMap.entries()).map(([month, data]) => ({ month, ...data }));

      const exportData: ExportData = {
        analytics: analyticsData,
        alertTypes,
        userRoles,
        incidentsTrends,
        allAlerts,
        allIncidents,
        allUsers,
        allGeofences,
      };

      await exportToPDF(exportData);
      toast.success('PDF exported successfully', { id: 'export-pdf' });
    } catch (error) {
      console.error('Error exporting PDF:', error);
      toast.error('Failed to export PDF', { id: 'export-pdf' });
    }
  };

  const handleExportCSV = async () => {
    if (!analyticsData) {
      toast.error('No analytics data available');
      return;
    }

    try {
      toast.loading('Preparing CSV export...', { id: 'export-csv' });
      
      // Fetch all detailed data
      const [allAlerts, allIncidents, allUsers, allGeofences] = await Promise.all([
        alertsService.getAll().catch(() => []),
        incidentsService.getAll().catch(() => []),
        usersService.getAll().catch(() => []),
        geofencesService.getAll().catch(() => []),
      ]);

      // Process alert types
      const alertTypesMap = new Map<string, number>();
      allAlerts.forEach(alert => {
        const type = alert.alert_type || 'Unknown';
        alertTypesMap.set(type, (alertTypesMap.get(type) || 0) + 1);
      });
      const alertTypes = Array.from(alertTypesMap.entries()).map(([name, value]) => ({ name, value }));

      // Process user roles
      const userRolesMap = new Map<string, number>();
      allUsers.forEach(user => {
        const role = user.role || 'Unknown';
        userRolesMap.set(role, (userRolesMap.get(role) || 0) + 1);
      });
      const userRoles = Array.from(userRolesMap.entries()).map(([name, value]) => ({ name, value }));

      // Process incidents trends (monthly)
      const incidentsTrendsMap = new Map<string, { resolved: number; unresolved: number }>();
      allIncidents.forEach(incident => {
        const date = new Date(incident.created_at);
        const monthKey = date.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
        const entry = incidentsTrendsMap.get(monthKey) || { resolved: 0, unresolved: 0 };
        if (incident.is_resolved) entry.resolved++;
        else entry.unresolved++;
        incidentsTrendsMap.set(monthKey, entry);
      });
      const incidentsTrends = Array.from(incidentsTrendsMap.entries()).map(([month, data]) => ({ month, ...data }));

      const exportData: ExportData = {
        analytics: analyticsData,
        alertTypes,
        userRoles,
        incidentsTrends,
        allAlerts,
        allIncidents,
        allUsers,
        allGeofences,
      };

      await exportToCSV(exportData);
      toast.success('CSV exported successfully', { id: 'export-csv' });
    } catch (error) {
      console.error('Error exporting CSV:', error);
      toast.error('Failed to export CSV', { id: 'export-csv' });
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        {/* Header Section */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground">Analytics & Reports</h1>
            <p className="text-muted-foreground mt-1">Comprehensive security insights and trends</p>
          </div>
        </div>

        {/* Stats Loading */}
        <CardLoading count={4} />

        {/* Charts Loading */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 bg-card p-6 rounded-lg shadow-md border">
            <div className="h-6 w-32 bg-muted rounded mb-4 animate-pulse"></div>
            <div className="h-80 bg-muted/40 rounded animate-pulse"></div>
          </div>
          <div className="lg:col-span-1 bg-card p-6 rounded-lg shadow-md border">
            <div className="h-6 w-32 bg-muted rounded mb-4 animate-pulse"></div>
            <div className="h-80 bg-muted/40 rounded animate-pulse"></div>
          </div>
        </div>

        {/* User Activity Loading */}
        <div className="bg-card p-6 rounded-lg shadow-md border">
          <div className="h-6 w-32 bg-muted rounded mb-4 animate-pulse"></div>
          <div className="h-64 bg-muted/40 rounded animate-pulse"></div>
        </div>

        {/* Table Loading */}
        <div className="bg-card p-6 rounded-lg shadow-md border">
          <div className="h-6 w-32 bg-muted rounded mb-4 animate-pulse"></div>
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex space-x-4 animate-pulse" style={{ animationDelay: `${i * 50}ms` }}>
                <div className="h-4 flex-1 bg-muted/60 rounded"></div>
                <div className="h-4 flex-1 bg-muted/60 rounded"></div>
                <div className="h-4 flex-1 bg-muted/60 rounded"></div>
                <div className="h-4 flex-1 bg-muted/60 rounded"></div>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Section */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Analytics & Reports</h1>
          <p className="text-muted-foreground mt-1">Comprehensive security insights and trends</p>
        </div>
        <div className="flex items-center gap-3">
          <DateRangeFilter dateRange={dateRange} onDateRangeChange={setDateRange} />
          <Button
            onClick={handleExportPDF}
            variant="outline"
            size="sm"
            className="text-xs"
          >
            <span className="material-icons text-sm mr-1">picture_as_pdf</span>
            Export PDF
          </Button>
          <Button
            onClick={handleExportCSV}
            variant="outline"
            size="sm"
            className="text-xs"
          >
            <span className="material-icons text-sm mr-1">table_chart</span>
            Export CSV
          </Button>
        </div>
      </div>

      {/* Analytics Stats */}
      <AnalyticsStats />

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Alert Trends - Takes 2 columns */}
        <div className="lg:col-span-2">
          <AlertTrendsChart />
        </div>

        {/* Alert Types - Takes 1 column */}
        <div className="lg:col-span-1">
          <AlertTypesChart />
        </div>
      </div>

      {/* User Activity Chart */}
      <UserActivityChart />

      {/* Additional Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Incidents Chart */}
        <IncidentsChart />

        {/* User Roles Chart */}
        <UserRolesChart />
      </div>

      {/* Recent Alert Logs Table */}
      <RecentLogsTable />
    </div>
  );
}



