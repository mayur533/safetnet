'use client';

import { useState, useEffect } from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useSearch } from '@/lib/contexts/search-context';
import { alertsService, Alert } from '@/lib/services/alerts';
import { TableLoading } from '@/components/ui/content-loading';
import { toast } from 'sonner';

interface AlertLog {
  id: string;
  timestamp: string;
  type: 'SOS' | 'Emergency' | 'Community' | 'Geofence' | 'System';
  location: string;
  user: string;
  status: 'resolved' | 'pending' | 'critical';
  responseTime: string;
}

export function RecentLogsTable() {
  const { searchQuery } = useSearch();
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(10);
  const [showPaginationMenu, setShowPaginationMenu] = useState(false);
  const [filterType, setFilterType] = useState<'all' | AlertLog['type']>('all');
  const [filterStatus, setFilterStatus] = useState<'all' | AlertLog['status']>('all');
  const [showFilterMenu, setShowFilterMenu] = useState(false);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchAlerts();
  }, []);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const data = await alertsService.getAll();
      setAlerts(data);
    } catch (error) {
      console.error('Error fetching alerts:', error);
      toast.error('Failed to fetch alerts');
    } finally {
      setLoading(false);
    }
  };

  // Convert real API alerts to table format
  const convertAlertsToLogs = (alerts: Alert[]): AlertLog[] => {
    return alerts.map((alert) => ({
      id: alert.id.toString(),
      timestamp: new Date(alert.created_at).toLocaleString(),
      type: alert.alert_type as AlertLog['type'],
      location: alert.location || 'Unknown',
      user: `User ${alert.user}`,
      status: alert.is_resolved ? 'resolved' : 'pending',
      responseTime: alert.resolved_at 
        ? `${Math.round((new Date(alert.resolved_at).getTime() - new Date(alert.created_at).getTime()) / 60000)} min`
        : 'N/A',
    }));
  };

  const alertLogs = convertAlertsToLogs(alerts);

  // Filter logs based on search query and filters
  const filteredLogs = alertLogs.filter((log) => {
    const matchesSearch = 
      log.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.location.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.user.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.status.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesType = filterType === 'all' || log.type === filterType;
    const matchesStatus = filterStatus === 'all' || log.status === filterStatus;

    return matchesSearch && matchesType && matchesStatus;
  });

  // Pagination
  const totalPages = Math.ceil(filteredLogs.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedLogs = filteredLogs.slice(startIndex, endIndex);

  const getStatusColor = (status: AlertLog['status']) => {
    switch (status) {
      case 'resolved':
        return 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300';
      case 'pending':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-300';
      case 'critical':
        return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-300';
    }
  };

  const getTypeColor = (type: AlertLog['type']) => {
    switch (type) {
      case 'SOS':
        return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300';
      case 'Emergency':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-300';
      case 'Community':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-300';
      case 'Geofence':
        return 'bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-300';
      case 'System':
        return 'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-300';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-300';
    }
  };

  if (loading) {
    return <TableLoading />;
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex items-center gap-4">
        <div className="relative">
          <button
            onClick={() => setShowFilterMenu(!showFilterMenu)}
            className="flex items-center gap-2 px-3 py-2 text-sm border rounded-md hover:bg-muted"
          >
            <span>Filters</span>
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
          
          {showFilterMenu && (
            <div className="absolute top-full left-0 mt-1 w-48 bg-white dark:bg-gray-800 border rounded-md shadow-lg z-10">
              <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase">
                Filter By Type
              </div>
              <button
                onClick={() => {
                  setFilterType('all');
                  setCurrentPage(1);
                  setShowFilterMenu(false);
                }}
                className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                  filterType === 'all'
                    ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                    : 'hover:bg-muted'
                }`}
              >
                All Types
              </button>
              {['SOS', 'Emergency', 'Community', 'Geofence', 'System'].map((type) => (
                <button
                  key={type}
                  onClick={() => {
                    setFilterType(type as AlertLog['type']);
                    setCurrentPage(1);
                    setShowFilterMenu(false);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                    filterType === type
                      ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                      : 'hover:bg-muted'
                  }`}
                >
                  {type}
                </button>
              ))}
              
              <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase border-t">
                Filter By Status
              </div>
              <button
                onClick={() => {
                  setFilterStatus('all');
                  setCurrentPage(1);
                  setShowFilterMenu(false);
                }}
                className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                  filterStatus === 'all'
                    ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                    : 'hover:bg-muted'
                }`}
              >
                All Status
              </button>
              {['resolved', 'pending', 'critical'].map((status) => (
                <button
                  key={status}
                  onClick={() => {
                    setFilterStatus(status as AlertLog['status']);
                    setCurrentPage(1);
                    setShowFilterMenu(false);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                    filterStatus === status
                      ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                      : 'hover:bg-muted'
                  }`}
                >
                  {status.charAt(0).toUpperCase() + status.slice(1)}
                </button>
              ))}
            </div>
          )}
        </div>
        
        <div className="text-sm text-muted-foreground">
          Showing {filteredLogs.length} of {alertLogs.length} logs
        </div>
      </div>

      {/* Table */}
      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>ID</TableHead>
              <TableHead>Timestamp</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Location</TableHead>
              <TableHead>User</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Response Time</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {paginatedLogs.map((log) => (
              <TableRow key={log.id}>
                <TableCell className="font-mono text-sm">{log.id}</TableCell>
                <TableCell className="text-sm">{log.timestamp}</TableCell>
                <TableCell>
                  <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getTypeColor(log.type)}`}>
                    {log.type}
                  </span>
                </TableCell>
                <TableCell className="text-sm">{log.location}</TableCell>
                <TableCell className="text-sm">{log.user}</TableCell>
                <TableCell>
                  <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(log.status)}`}>
                    {log.status}
                  </span>
                </TableCell>
                <TableCell className="text-sm">{log.responseTime}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Show</span>
            <div className="relative">
              <button
                onClick={() => setShowPaginationMenu(!showPaginationMenu)}
                className="flex items-center gap-1 px-2 py-1 text-sm border rounded hover:bg-muted"
              >
                {itemsPerPage}
                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              
              {showPaginationMenu && (
                <div className="absolute top-full left-0 mt-1 w-20 bg-white dark:bg-gray-800 border rounded-md shadow-lg z-10">
                  {[5, 10, 25, 50].map((size) => (
                    <button
                      key={size}
                      onClick={() => {
                        setItemsPerPage(size);
                        setCurrentPage(1);
                        setShowPaginationMenu(false);
                      }}
                      className={`w-full text-left px-2 py-1 text-sm transition-colors ${
                        itemsPerPage === size
                          ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                          : 'hover:bg-muted'
                      }`}
                    >
                      {size}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <span className="text-sm text-muted-foreground">per page</span>
          </div>
          
          <div className="flex items-center gap-2">
            <button
              onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
              disabled={currentPage === 1}
              className="px-3 py-1 text-sm border rounded hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            
            <span className="text-sm text-muted-foreground">
              Page {currentPage} of {totalPages}
            </span>
            
            <button
              onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
              disabled={currentPage === totalPages}
              className="px-3 py-1 text-sm border rounded hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}