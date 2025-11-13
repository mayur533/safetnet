'use client';

import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { toast } from 'sonner';
import { alertsService, Alert } from '@/lib/services/alerts';
import { CardLoading, TableLoading } from '@/components/ui/content-loading';
import { useSearch } from '@/lib/contexts/search-context';

export default function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [sortBy, setSortBy] = useState('date');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [itemsPerPage, setItemsPerPage] = useState(10);
  const [currentPage, setCurrentPage] = useState(1);
  const [filterStatus, setFilterStatus] = useState('all');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const { searchQuery } = useSearch();
  
  // Dropdown menus
  const [showSortMenu, setShowSortMenu] = useState(false);
  const [showPerPageMenu, setShowPerPageMenu] = useState(false);
  const [showFilterMenu, setShowFilterMenu] = useState(false);
  
  // Modals
  const [viewDetailsAlert, setViewDetailsAlert] = useState<Alert | null>(null);
  const [deleteAlertId, setDeleteAlertId] = useState<number | null>(null);

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

  const handleResolve = async (id: number) => {
    try {
      await alertsService.resolve(id);
      toast.success('Alert resolved successfully');
      fetchAlerts();
    } catch (error) {
      console.error('Error resolving alert:', error);
      toast.error('Failed to resolve alert');
    }
  };

  const confirmDelete = async () => {
    if (!deleteAlertId) return;

    try {
      await alertsService.delete(deleteAlertId);
      toast.success('Alert deleted successfully');
      setDeleteAlertId(null);
      fetchAlerts();
    } catch (error) {
      console.error('Error deleting alert:', error);
      toast.error('Failed to delete alert');
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getSeverityBadge = (severity: string) => {
    const badges: { [key: string]: string } = {
      low: 'bg-blue-100 text-blue-800 border-blue-200',
      medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      high: 'bg-orange-100 text-orange-800 border-orange-200',
      critical: 'bg-red-100 text-red-800 border-red-200',
    };

    return (
      <Badge className={badges[severity] || badges.low}>
        <span className="w-2 h-2 bg-current rounded-full mr-2"></span>
        {severity.charAt(0).toUpperCase() + severity.slice(1)}
      </Badge>
    );
  };

  const getStatusBadge = (isResolved: boolean) => {
    if (isResolved) {
      return (
        <Badge className="bg-green-100 text-green-800 border-green-200">
          <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
          Resolved
        </Badge>
      );
    }
    return (
      <Badge variant="outline" className="text-orange-600 border-orange-200">
        <span className="w-2 h-2 bg-orange-500 rounded-full mr-2"></span>
        Pending
      </Badge>
    );
  };

  // Filter
  const filteredAlerts = alerts.filter((alert) => {
    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      if (
        !alert.message?.toLowerCase().includes(query) &&
        !alert.alert_type?.toLowerCase().includes(query) &&
        !alert.severity?.toLowerCase().includes(query) &&
        !alert.location?.toLowerCase().includes(query) &&
        !alert.geofence_name?.toLowerCase().includes(query) &&
        !alert.user_username?.toLowerCase().includes(query) &&
        !alert.id.toString().includes(query)
      ) {
        return false;
      }
    }
    
    const statusMatch = filterStatus === 'all' || 
      (filterStatus === 'resolved' && alert.is_resolved) ||
      (filterStatus === 'pending' && !alert.is_resolved);
    
    const severityMatch = filterSeverity === 'all' || alert.severity === filterSeverity;
    
    return statusMatch && severityMatch;
  });

  // Sort
  const sortedAlerts = [...filteredAlerts].sort((a, b) => {
    let comparison = 0;
    
    switch (sortBy) {
      case 'severity':
        const severityOrder = { low: 1, medium: 2, high: 3, critical: 4 };
        comparison = (severityOrder[a.severity] || 0) - (severityOrder[b.severity] || 0);
        break;
      case 'type':
        comparison = (a.alert_type || '').localeCompare(b.alert_type || '');
        break;
      case 'date':
      default:
        comparison = new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
        break;
    }
    
    return sortOrder === 'asc' ? comparison : -comparison;
  });

  // Pagination
  const totalPages = Math.ceil(sortedAlerts.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const paginatedAlerts = sortedAlerts.slice(startIndex, startIndex + itemsPerPage);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Alerts Management</h1>
          <p className="text-muted-foreground mt-1">Monitor and manage all security alerts</p>
        </div>
      </div>

      {/* Stats Cards */}
      {loading ? (
        <CardLoading count={4} />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-indigo-500 to-indigo-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-indigo-100">Total Alerts</p>
                <h3 className="text-2xl font-bold mt-1">{alerts.length}</h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                notifications_active
              </span>
            </div>
          </div>
          
          <div className="bg-gradient-to-br from-red-500 to-red-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-red-100">Critical Alerts</p>
                <h3 className="text-2xl font-bold mt-1">
                  {alerts.filter(a => a.severity === 'critical').length}
                </h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                warning
              </span>
            </div>
          </div>
          
          <div className="bg-gradient-to-br from-orange-500 to-orange-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-orange-100">Pending</p>
                <h3 className="text-2xl font-bold mt-1">
                  {alerts.filter(a => !a.is_resolved).length}
                </h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                pending
              </span>
            </div>
          </div>
          
          <div className="bg-gradient-to-br from-green-500 to-green-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-green-100">Resolved</p>
                <h3 className="text-2xl font-bold mt-1">
                  {alerts.filter(a => a.is_resolved).length}
                </h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                check_circle
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Table Card */}
      {loading ? (
        <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
          {/* Controls Loading */}
          <div className="flex items-center justify-end gap-3 mb-6 animate-pulse">
            <div className="h-10 w-32 bg-muted rounded-lg"></div>
            <div className="h-10 w-24 bg-muted rounded-lg"></div>
            <div className="h-10 w-24 bg-muted rounded-lg"></div>
          </div>

          {/* Table Loading */}
          <TableLoading rows={itemsPerPage} columns={7} />

          {/* Pagination Info Loading */}
          <div className="mt-4 flex items-center justify-between animate-pulse">
            <div className="h-4 w-48 bg-muted rounded"></div>
            <div className="h-4 w-48 bg-muted rounded"></div>
          </div>
        </div>
      ) : (
        <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
          <>
            {/* Controls - Right Aligned */}
            <div className="flex items-center justify-end gap-3 mb-6">
              {/* Pagination Button */}
              <div className="relative">
                <button
                  onClick={() => {
                    setShowPerPageMenu(!showPerPageMenu);
                    setShowSortMenu(false);
                    setShowFilterMenu(false);
                  }}
                  className="flex items-center gap-2 px-4 py-2 bg-background border border-border rounded-lg hover:bg-muted transition-colors"
                >
                  <span className="material-icons text-lg">apps</span>
                  <span className="text-sm font-medium">Pagination</span>
                </button>

                {showPerPageMenu && (
                  <div className="absolute right-0 mt-2 w-56 bg-card border border-border rounded-lg shadow-lg z-10">
                    <div className="p-2">
                      <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase">
                        Items per page
                      </div>
                      {[10, 25, 50, 100].map((count) => (
                        <button
                          key={count}
                          onClick={() => {
                            setItemsPerPage(count);
                            setCurrentPage(1);
                            setShowPerPageMenu(false);
                          }}
                          className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                            itemsPerPage === count
                              ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                              : 'hover:bg-muted'
                          }`}
                        >
                          {count} items
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Filter Button */}
              <div className="relative">
                <button
                  onClick={() => {
                    setShowFilterMenu(!showFilterMenu);
                    setShowSortMenu(false);
                    setShowPerPageMenu(false);
                  }}
                  className="flex items-center gap-2 px-4 py-2 bg-background border border-border rounded-lg hover:bg-muted transition-colors"
                >
                  <span className="material-icons text-lg">filter_list</span>
                  <span className="text-sm font-medium">Filter</span>
                  {(filterStatus !== 'all' || filterSeverity !== 'all') && (
                    <span className="w-2 h-2 bg-indigo-600 rounded-full"></span>
                  )}
                </button>

                {showFilterMenu && (
                  <div className="absolute right-0 mt-2 w-56 bg-card border border-border rounded-lg shadow-lg z-10">
                    <div className="p-2">
                      <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase">
                        Status
                      </div>
                      {['all', 'pending', 'resolved'].map((status) => (
                        <button
                          key={status}
                          onClick={() => {
                            setFilterStatus(status);
                            setCurrentPage(1);
                            setShowFilterMenu(false);
                          }}
                          className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                            filterStatus === status
                              ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                              : 'hover:bg-muted'
                          }`}
                        >
                          {status === 'all' ? 'All Status' : status.charAt(0).toUpperCase() + status.slice(1)}
                        </button>
                      ))}
                      <div className="border-t border-border my-2"></div>
                      <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase">
                        Severity
                      </div>
                      {['all', 'low', 'medium', 'high', 'critical'].map((severity) => (
                        <button
                          key={severity}
                          onClick={() => {
                            setFilterSeverity(severity);
                            setCurrentPage(1);
                            setShowFilterMenu(false);
                          }}
                          className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                            filterSeverity === severity
                              ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                              : 'hover:bg-muted'
                          }`}
                        >
                          {severity === 'all' ? 'All Severity' : severity.charAt(0).toUpperCase() + severity.slice(1)}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Sort Button */}
              <div className="relative">
                <button
                  onClick={() => {
                    setShowSortMenu(!showSortMenu);
                    setShowPerPageMenu(false);
                    setShowFilterMenu(false);
                  }}
                  className="flex items-center gap-2 px-4 py-2 bg-background border border-border rounded-lg hover:bg-muted transition-colors"
                >
                  <span className="material-icons text-lg">sort</span>
                  <span className="text-sm font-medium">Sort</span>
                </button>

                {showSortMenu && (
                  <div className="absolute right-0 mt-2 w-56 bg-card border border-border rounded-lg shadow-lg z-10">
                    <div className="p-2">
                      <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase">
                        Sort By
                      </div>
                      <button
                        onClick={() => {
                          if (sortBy === 'date') {
                            setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                          } else {
                            setSortBy('date');
                            setSortOrder('desc');
                          }
                          setCurrentPage(1);
                        }}
                        className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                          sortBy === 'date'
                            ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                            : 'hover:bg-muted'
                        }`}
                      >
                        <span>Date Created</span>
                        {sortBy === 'date' && (
                          <span className="text-xs font-medium">{sortOrder === 'desc' ? 'Newest' : 'Oldest'}</span>
                        )}
                      </button>
                      <button
                        onClick={() => {
                          if (sortBy === 'severity') {
                            setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                          } else {
                            setSortBy('severity');
                            setSortOrder('asc');
                          }
                          setCurrentPage(1);
                        }}
                        className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                          sortBy === 'severity'
                            ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                            : 'hover:bg-muted'
                        }`}
                      >
                        <span>Severity</span>
                        {sortBy === 'severity' && (
                          <span className="text-xs font-medium">{sortOrder === 'asc' ? 'A-Z' : 'Z-A'}</span>
                        )}
                      </button>
                      <button
                        onClick={() => {
                          if (sortBy === 'type') {
                            setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                          } else {
                            setSortBy('type');
                            setSortOrder('asc');
                          }
                          setCurrentPage(1);
                        }}
                        className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                          sortBy === 'type'
                            ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                            : 'hover:bg-muted'
                        }`}
                      >
                        <span>Type</span>
                        {sortBy === 'type' && (
                          <span className="text-xs font-medium">{sortOrder === 'asc' ? 'A-Z' : 'Z-A'}</span>
                        )}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Table */}
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="py-4 px-4">Alert ID</TableHead>
                    <TableHead className="py-4 px-4">Type</TableHead>
                    <TableHead className="py-4 px-4">Message</TableHead>
                    <TableHead className="py-4 px-4">Severity</TableHead>
                    <TableHead className="py-4 px-4">Location</TableHead>
                    <TableHead className="py-4 px-4">Status</TableHead>
                    <TableHead className="py-4 px-4 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {paginatedAlerts.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                        <div className="flex flex-col items-center gap-2">
                          <span className="material-icons text-4xl">notifications_off</span>
                          <p>No alerts found</p>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    paginatedAlerts.map((alert) => (
                      <TableRow key={alert.id}>
                        <TableCell className="py-4 px-4">
                          <Badge variant="outline" className="font-mono">
                            ALT-{alert.id}
                          </Badge>
                        </TableCell>
                        <TableCell className="py-4 px-4">
                          <span className="text-sm">{alert.alert_type || 'N/A'}</span>
                        </TableCell>
                        <TableCell className="py-4 px-4">
                          <span className="text-sm max-w-xs truncate block">
                            {alert.message || 'No message'}
                          </span>
                        </TableCell>
                        <TableCell className="py-4 px-4">
                          {getSeverityBadge(alert.severity)}
                        </TableCell>
                        <TableCell className="py-4 px-4">
                          <span className="text-sm">{alert.location || alert.geofence_name || 'N/A'}</span>
                        </TableCell>
                        <TableCell className="py-4 px-4">
                          {getStatusBadge(alert.is_resolved)}
                        </TableCell>
                        <TableCell className="py-4 px-4 text-right">
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm">
                                <span className="material-icons text-lg">more_vert</span>
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem onClick={() => setViewDetailsAlert(alert)}>
                                <span className="material-icons text-sm mr-2">visibility</span>
                                View Details
                              </DropdownMenuItem>
                              {!alert.is_resolved && (
                                <DropdownMenuItem onClick={() => handleResolve(alert.id)}>
                                  <span className="material-icons text-sm mr-2">check_circle</span>
                                  Mark as Resolved
                                </DropdownMenuItem>
                              )}
                              <DropdownMenuItem
                                onClick={() => setDeleteAlertId(alert.id)}
                                className="text-red-600"
                              >
                                <span className="material-icons text-sm mr-2">delete</span>
                                Delete
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>

            {/* Table Info */}
            <div className="mt-4 flex items-center justify-between text-sm text-muted-foreground">
              <p>
                Showing {startIndex + 1}-{Math.min(startIndex + itemsPerPage, sortedAlerts.length)} of {sortedAlerts.length} alerts
                {(filterStatus !== 'all' || filterSeverity !== 'all') && (
                  <span className="ml-2 text-indigo-600 font-medium">(Filtered)</span>
                )}
              </p>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    if (currentPage > 1) {
                      setCurrentPage(currentPage - 1);
                    }
                  }}
                  disabled={currentPage === 1}
                  className={`${currentPage === 1 ? 'opacity-50 cursor-not-allowed' : 'hover:text-foreground cursor-pointer'}`}
                >
                  <span className="material-icons text-lg">chevron_left</span>
                </button>
                <button
                  onClick={() => {
                    if (currentPage < totalPages) {
                      setCurrentPage(currentPage + 1);
                    }
                  }}
                  disabled={currentPage === totalPages}
                  className={`${currentPage === totalPages ? 'opacity-50 cursor-not-allowed' : 'hover:text-foreground cursor-pointer'}`}
                >
                  <span className="material-icons text-lg">chevron_right</span>
                </button>
                <p>
                  Page {currentPage} of {totalPages || 1} • Sorted by: {sortBy === 'date' ? 'Date' : sortBy === 'severity' ? 'Severity' : 'Type'} ({sortOrder === 'asc' ? 'Asc' : 'Desc'})
                </p>
              </div>
            </div>
          </>
        </div>
      )}

      {/* View Details Modal */}
      {viewDetailsAlert && (
        <Dialog open={!!viewDetailsAlert} onOpenChange={() => setViewDetailsAlert(null)}>
          <DialogContent className="sm:max-w-[600px]">
            <DialogHeader>
              <DialogTitle className="text-2xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
                Alert Details
              </DialogTitle>
            </DialogHeader>

            <div className="space-y-4 py-4">
              {/* Alert ID */}
              <div className="space-y-1">
                <Label className="text-sm font-medium text-muted-foreground">Alert ID</Label>
                <Badge variant="outline" className="font-mono">
                  ALT-{viewDetailsAlert.id}
                </Badge>
              </div>

              {/* Type and Severity */}
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Type</Label>
                  <p className="text-base font-semibold">{viewDetailsAlert.alert_type || 'N/A'}</p>
                </div>
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Severity</Label>
                  <div>{getSeverityBadge(viewDetailsAlert.severity)}</div>
                </div>
              </div>

              {/* Message */}
              <div className="space-y-1">
                <Label className="text-sm font-medium text-muted-foreground">Message</Label>
                <p className="text-sm bg-muted/50 p-3 rounded-lg">
                  {viewDetailsAlert.message || 'No message'}
                </p>
              </div>

              {/* Location */}
              <div className="space-y-1">
                <Label className="text-sm font-medium text-muted-foreground">Location</Label>
                <p className="text-sm">{viewDetailsAlert.location || viewDetailsAlert.geofence_name || 'N/A'}</p>
              </div>

              {/* User */}
              {viewDetailsAlert.user_username && (
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">User</Label>
                  <p className="text-sm">{viewDetailsAlert.user_username}</p>
                </div>
              )}

              {/* Status and Resolution */}
              <div className="grid grid-cols-2 gap-4 pt-4 border-t">
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Status</Label>
                  <div>{getStatusBadge(viewDetailsAlert.is_resolved)}</div>
                </div>
                {viewDetailsAlert.is_resolved && viewDetailsAlert.resolved_at && (
                  <div className="space-y-1">
                    <Label className="text-sm font-medium text-muted-foreground">Resolved At</Label>
                    <p className="text-sm">{formatDate(viewDetailsAlert.resolved_at)}</p>
                  </div>
                )}
              </div>

              {viewDetailsAlert.resolved_by_username && (
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Resolved By</Label>
                  <p className="text-sm">{viewDetailsAlert.resolved_by_username}</p>
                </div>
              )}

              {/* Timestamps */}
              <div className="grid grid-cols-2 gap-4 pt-4 border-t">
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Created</Label>
                  <p className="text-sm">{formatDate(viewDetailsAlert.created_at)}</p>
                </div>
                {viewDetailsAlert.response_time && (
                  <div className="space-y-1">
                    <Label className="text-sm font-medium text-muted-foreground">Response Time</Label>
                    <p className="text-sm">{viewDetailsAlert.response_time} min</p>
                  </div>
                )}
              </div>
            </div>

            <DialogFooter>
              <Button variant="outline" onClick={() => setViewDetailsAlert(null)}>
                Close
              </Button>
              {!viewDetailsAlert.is_resolved && (
                <Button
                  onClick={() => {
                    handleResolve(viewDetailsAlert.id);
                    setViewDetailsAlert(null);
                  }}
                  className="bg-gradient-to-r from-green-600 to-green-700"
                >
                  <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>
                    check_circle
                  </span>
                  Resolve
                </Button>
              )}
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deleteAlertId} onOpenChange={() => setDeleteAlertId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you sure?</AlertDialogTitle>
            <AlertDialogDescription>
              This will permanently delete this alert. This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              className="bg-red-600 hover:bg-red-700"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}




