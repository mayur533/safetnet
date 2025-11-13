'use client';

import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
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
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { CardLoading, TableLoading } from '@/components/ui/content-loading';
import { incidentsService, type Incident as BackendIncident } from '@/lib/services/incidents';
import { useSearch } from '@/lib/contexts/search-context';

type Incident = BackendIncident;

type SortField = 'id' | 'incident_type' | 'severity' | 'geofence' | 'created_at' | 'type' | 'status' | 'priority' | 'reportedBy' | 'assignedOfficer' | 'timestamp';
type SortOrder = 'asc' | 'desc';

export default function IncidentLogsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [filterGeofence, setFilterGeofence] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [dateRange, setDateRange] = useState<string>('all');
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [viewDetailsIncident, setViewDetailsIncident] = useState<Incident | null>(null);
  const [deleteIncidentId, setDeleteIncidentId] = useState<number | null>(null);
  const [showFilterMenu, setShowFilterMenu] = useState(false);
  const [showSortMenu, setShowSortMenu] = useState(false);
  const [showPerPageMenu, setShowPerPageMenu] = useState(false);
  const [showDateMenu, setShowDateMenu] = useState(false);
  const [sortField, setSortField] = useState<SortField>('timestamp');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(10);

  // Fetch incidents on mount
  useEffect(() => {
    fetchIncidents();
  }, []);

  const fetchIncidents = async () => {
    try {
      setIsLoading(true);
      const data = await incidentsService.getAll();
      setIncidents(data);
    } catch (error: unknown) {
      console.error('Failed to fetch incidents:', error);
      toast.error('Failed to load incidents');
    } finally {
      setIsLoading(false);
    }
  };

  // Get search query
  const { searchQuery } = useSearch();

  // Filter
  const filteredIncidents = incidents.filter((incident) => {
    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      const locationString = typeof incident.location === 'object' 
        ? JSON.stringify(incident.location) 
        : (incident.location || '');
      
      if (
        !incident.title?.toLowerCase().includes(query) &&
        !incident.details?.toLowerCase().includes(query) &&
        !incident.incident_type?.toLowerCase().includes(query) &&
        !incident.severity?.toLowerCase().includes(query) &&
        !locationString.toLowerCase().includes(query) &&
        !incident.geofence_name?.toLowerCase().includes(query) &&
        !incident.officer_name?.toLowerCase().includes(query) &&
        !incident.id.toString().includes(query)
      ) {
        return false;
      }
    }
    
    const matchesGeofence = filterGeofence === 'all' || incident.geofence.toString() === filterGeofence;
    
    // Convert is_resolved to status for filtering
    let status = 'open';
    if (incident.is_resolved && incident.resolved_at) {
      status = 'resolved';
    } else if (!incident.is_resolved) {
      status = 'in-progress';
    }
    
    const matchesStatus = filterStatus === 'all' || status === filterStatus;
    return matchesGeofence && matchesStatus;
  });

  // Sort
  const sortedIncidents = [...filteredIncidents].sort((a, b) => {
    const aValue = a[sortField as keyof Incident];
    const bValue = b[sortField as keyof Incident];

    // Handle null/undefined values
    if (aValue === null || aValue === undefined) return 1;
    if (bValue === null || bValue === undefined) return -1;

    // Handle date sorting
    if (sortField === 'timestamp' || sortField === 'created_at') {
      const aDate = new Date(aValue as string).getTime();
      const bDate = new Date(bValue as string).getTime();
      return sortOrder === 'asc' ? aDate - bDate : bDate - aDate;
    }

    // Handle string/number sorting
    if (sortOrder === 'asc') {
      return String(aValue).localeCompare(String(bValue));
    } else {
      return String(bValue).localeCompare(String(aValue));
    }
  });

  // Pagination
  const totalPages = Math.ceil(sortedIncidents.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedIncidents = sortedIncidents.slice(startIndex, endIndex);

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'emergency': return 'emergency';
      case 'security': return 'security';
      case 'medical': return 'medical_services';
      case 'fire': return 'local_fire_department';
      case 'maintenance': return 'build';
      case 'other': return 'report_problem';
      default: return 'report';
    }
  };

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const getTypeColor = (type: string) => {
    switch (type) {
      case 'emergency': return 'bg-red-100 text-red-800';
      case 'security': return 'bg-orange-100 text-orange-800';
      case 'medical': return 'bg-blue-100 text-blue-800';
      case 'fire': return 'bg-red-200 text-red-900';
      case 'maintenance': return 'bg-yellow-100 text-yellow-800';
      case 'other': return 'bg-gray-100 text-gray-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getStatusBadge = (incident: Incident) => {
    if (incident.is_resolved && incident.resolved_at) {
      return (
        <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 border border-green-200">
          <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
          Resolved
        </span>
      );
    } else if (!incident.is_resolved) {
      return (
        <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800 border border-blue-200">
          <span className="w-2 h-2 bg-blue-500 rounded-full mr-2"></span>
          In Progress
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 border border-yellow-200">
        <span className="w-2 h-2 bg-yellow-500 rounded-full mr-2"></span>
        Open
      </span>
    );
  };

  const formatDate = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  };

  const formatTime = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  };

  const confirmDelete = async () => {
    if (!deleteIncidentId) return;
    
    try {
      await incidentsService.delete(deleteIncidentId);
      toast.success('Incident deleted successfully');
      setDeleteIncidentId(null);
      fetchIncidents(); // Refresh list
    } catch (error: unknown) {
      console.error('Delete error:', error);
      toast.error(error instanceof Error ? error.message : 'Failed to delete incident');
    }
  };

  const handleResolve = async (id: number) => {
    try {
      await incidentsService.resolve(id);
      toast.success('Incident marked as resolved');
      fetchIncidents(); // Refresh list
    } catch (error: unknown) {
      console.error('Resolve error:', error);
      toast.error(error instanceof Error ? error.message : 'Failed to resolve incident');
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">All Incidents</h1>
            <p className="text-muted-foreground mt-1">Monitor and manage all security incidents across the system</p>
          </div>
        </div>

        {/* Stats Loading */}
        <CardLoading count={4} />

        {/* Table Container Loading */}
        <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
          <div className="space-y-3 animate-pulse">
            <div className="flex justify-end gap-3 mb-6">
              <div className="h-10 w-32 bg-muted rounded-lg"></div>
              <div className="h-10 w-24 bg-muted rounded-lg"></div>
              <div className="h-10 w-24 bg-muted rounded-lg"></div>
            </div>
            <TableLoading rows={10} columns={7} />
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">All Incidents</h1>
          <p className="text-muted-foreground mt-1">Monitor and manage all security incidents across the system</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-indigo-500 to-indigo-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-indigo-100">Total Incidents</p>
                <h3 className="text-2xl font-bold mt-1">{incidents.length}</h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                report
              </span>
            </div>
          </div>
          <div className="bg-gradient-to-br from-yellow-500 to-yellow-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-yellow-100">Open</p>
                <h3 className="text-2xl font-bold mt-1">
                  {incidents.filter(i => !i.is_resolved).length}
                </h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                pending
              </span>
            </div>
          </div>
          <div className="bg-gradient-to-br from-blue-500 to-blue-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-blue-100">Critical</p>
                <h3 className="text-2xl font-bold mt-1">
                  {incidents.filter(i => i.severity === 'CRITICAL').length}
                </h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                priority_high
              </span>
            </div>
          </div>
          <div className="bg-gradient-to-br from-green-500 to-green-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-green-100">Resolved</p>
                <h3 className="text-2xl font-bold mt-1">
                  {incidents.filter(i => i.is_resolved).length}
                </h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                check_circle
              </span>
            </div>
          </div>
      </div>

      {/* Table Container with Controls */}
      <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
        {/* Filter, Sort, and Pagination Controls - Right Aligned */}
        <div className="flex items-center justify-end gap-3 mb-6">
          {/* Pagination Button */}
          <div className="relative">
            <button
              onClick={() => {
                setShowPerPageMenu(!showPerPageMenu);
                setShowFilterMenu(false);
                setShowSortMenu(false);
                setShowDateMenu(false);
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

          {/* Date Range Filter */}
          <div className="relative">
            <button
              onClick={() => {
                setShowDateMenu(!showDateMenu);
                setShowFilterMenu(false);
                setShowSortMenu(false);
                setShowPerPageMenu(false);
              }}
              className="flex items-center gap-2 px-4 py-2 bg-background border border-border rounded-lg hover:bg-muted transition-colors"
            >
              <span className="material-icons text-lg">calendar_today</span>
              <span className="text-sm font-medium">Date Range</span>
              {dateRange !== 'all' && (
                <span className="w-2 h-2 bg-indigo-600 rounded-full"></span>
              )}
            </button>

            {showDateMenu && (
              <div className="absolute right-0 mt-2 w-48 bg-card border border-border rounded-lg shadow-lg z-10">
                <div className="p-2">
                  {['all', 'today', 'week', 'month'].map((range) => (
                    <button
                      key={range}
                      onClick={() => {
                        setDateRange(range);
                        setShowDateMenu(false);
                      }}
                      className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                        dateRange === range
                          ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                          : 'hover:bg-muted'
                      }`}
                    >
                      {range === 'all' ? 'All Time' : range === 'today' ? 'Today' : range === 'week' ? 'This Week' : 'This Month'}
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
                setShowDateMenu(false);
                setShowSortMenu(false);
                setShowPerPageMenu(false);
              }}
              className="flex items-center gap-2 px-4 py-2 bg-background border border-border rounded-lg hover:bg-muted transition-colors"
            >
              <span className="material-icons text-lg">filter_list</span>
              <span className="text-sm font-medium">Filter</span>
              {(filterStatus !== 'all' || filterGeofence !== 'all') && (
                <span className="w-2 h-2 bg-indigo-600 rounded-full"></span>
              )}
            </button>

            {showFilterMenu && (
              <div className="absolute right-0 mt-2 w-56 bg-card border border-border rounded-lg shadow-lg z-10">
                <div className="p-2">
                  <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase">
                    Geofence
                  </div>
                  <select
                    value={filterGeofence}
                    onChange={(e) => {
                      setFilterGeofence(e.target.value);
                      setCurrentPage(1);
                    }}
                    className="w-full px-3 py-2 mb-2 border rounded-md text-sm"
                  >
                    <option value="all">All Geofences</option>
                    <option value="North Gate">North Gate</option>
                    <option value="East Sector">East Sector</option>
                    <option value="West Zone">West Zone</option>
                    <option value="South Entrance">South Entrance</option>
                    <option value="Central Park">Central Park</option>
                    <option value="Main Entrance">Main Entrance</option>
                    <option value="Parking Area B">Parking Area B</option>
                    <option value="Recreation Center">Recreation Center</option>
                  </select>

                  <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase">
                    Status
                  </div>
                  {['all', 'open', 'in-progress', 'resolved', 'closed'].map((status) => (
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
                      {status === 'all' ? 'All Status' : status.replace('-', ' ')}
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
                setShowFilterMenu(false);
                setShowDateMenu(false);
                setShowPerPageMenu(false);
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
                      if (sortField === 'timestamp') {
                        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                      } else {
                        setSortField('timestamp');
                        setSortOrder('desc');
                      }
                      setCurrentPage(1);
                    }}
                    className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                      sortField === 'timestamp'
                        ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                        : 'hover:bg-muted'
                    }`}
                  >
                    <span>Date</span>
                    {sortField === 'timestamp' && (
                      <span className="text-xs font-medium">{sortOrder === 'desc' ? 'Newest' : 'Oldest'}</span>
                    )}
                  </button>
                  <button
                    onClick={() => {
                      if (sortField === 'id') {
                        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                      } else {
                        setSortField('id');
                        setSortOrder('asc');
                      }
                      setCurrentPage(1);
                    }}
                    className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                      sortField === 'id'
                        ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                        : 'hover:bg-muted'
                    }`}
                  >
                    <span>Incident ID</span>
                    {sortField === 'id' && (
                      <span className="text-xs font-medium">{sortOrder === 'asc' ? 'A-Z' : 'Z-A'}</span>
                    )}
                  </button>
                  <button
                    onClick={() => {
                      if (sortField === 'type') {
                        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                      } else {
                        setSortField('type');
                        setSortOrder('asc');
                      }
                      setCurrentPage(1);
                    }}
                    className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                      sortField === 'type'
                        ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                        : 'hover:bg-muted'
                    }`}
                  >
                    <span>Type</span>
                    {sortField === 'type' && (
                      <span className="text-xs font-medium">{sortOrder === 'asc' ? 'A-Z' : 'Z-A'}</span>
                    )}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Table */}
        <div className="overflow-x-auto rounded-xl border border-border/50">
            <Table>
              <TableHeader>
                <TableRow className="border-b bg-muted/30 hover:bg-muted/30">
                  <TableHead className="text-muted-foreground text-sm font-semibold">Incident ID</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold">Title & Type</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold">Severity</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold">Geofence</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold">Date</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold">Status</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paginatedIncidents.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-12">
                    <span className="material-icons text-6xl text-muted-foreground mb-2">
                      search_off
                    </span>
                    <p className="text-muted-foreground">No incidents found</p>
                  </TableCell>
                </TableRow>
              ) : (
                paginatedIncidents.map((incident) => (
                  <TableRow key={incident.id} className="border-b hover:bg-muted/20 transition-colors">
                    <TableCell className="py-4 px-4">
                      <span className="text-sm font-mono">INC-{incident.id}</span>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <div className="space-y-1">
                        <div className="text-sm font-medium">{incident.title}</div>
                        <Badge variant="outline" className="text-xs">
                          {incident.incident_type.replace(/_/g, ' ')}
                        </Badge>
                      </div>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <Badge variant="outline" className={`text-xs ${
                        incident.severity === 'HIGH' ? 'border-red-500 text-red-700' :
                        incident.severity === 'MEDIUM' ? 'border-orange-500 text-orange-700' :
                        'border-green-500 text-green-700'
                      }`}>
                        {incident.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <div className="flex items-center space-x-2">
                        <span className="material-icons text-sm text-indigo-600">location_on</span>
                        <span className="text-sm">{incident.geofence_name || `Geofence #${incident.geofence}`}</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <div className="text-sm">{formatDate(incident.created_at)}</div>
                      <div className="text-xs text-muted-foreground">{formatTime(incident.created_at)}</div>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      {getStatusBadge(incident)}
                    </TableCell>
                    <TableCell className="py-4 px-4 text-right">
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="sm" className="h-8 w-8 p-0 hover:bg-muted">
                            <span className="material-icons text-lg">more_vert</span>
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-48">
                          <DropdownMenuItem
                            className="cursor-pointer"
                            onClick={() => setViewDetailsIncident(incident)}
                          >
                            <span className="material-icons text-sm mr-2">visibility</span>
                            View Details
                          </DropdownMenuItem>
                          {!incident.is_resolved && (
                            <DropdownMenuItem
                              className="cursor-pointer text-green-600 focus:text-green-600"
                              onClick={() => handleResolve(incident.id)}
                            >
                              <span className="material-icons text-sm mr-2">check_circle</span>
                              Mark as Resolved
                            </DropdownMenuItem>
                          )}
                          <DropdownMenuItem 
                            className="cursor-pointer text-red-600 focus:text-red-600"
                            onClick={() => setDeleteIncidentId(incident.id)}
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
            Showing {startIndex + 1}-{Math.min(endIndex, sortedIncidents.length)} of {sortedIncidents.length} incidents
            {(filterStatus !== 'all' || filterGeofence !== 'all') && (
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
              Page {currentPage} of {totalPages} • Sorted by: {sortField} ({sortOrder === 'asc' ? 'Asc' : 'Desc'})
            </p>
          </div>
        </div>
      </div>

      {/* View Details Modal */}
      {viewDetailsIncident && (
        <Dialog open={!!viewDetailsIncident} onOpenChange={() => setViewDetailsIncident(null)}>
          <DialogContent className="sm:max-w-[700px] bg-card/95 backdrop-blur-xl border-border/50 p-4">
            <DialogHeader>
              <DialogTitle className="text-2xl font-bold flex items-center bg-gradient-to-r from-indigo-600 to-blue-600 bg-clip-text text-transparent">
                <span className="material-icons text-indigo-600 mr-2">
                  report_problem
                </span>
                Incident Details
              </DialogTitle>
              <DialogDescription>
                Complete information about this incident
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3 mt-3">
              {/* Incident Header */}
              <div className="space-y-2 p-4 bg-gradient-to-r from-indigo-50 to-blue-50 dark:from-indigo-950/30 dark:to-blue-950/30 rounded-lg border border-indigo-200 dark:border-indigo-800">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold">{viewDetailsIncident.title}</h3>
                  {getStatusBadge(viewDetailsIncident)}
                </div>
                <p className="text-sm text-muted-foreground">{viewDetailsIncident.details}</p>
              </div>

              {/* Incident Info Grid */}
              <div className="grid grid-cols-2 gap-4">
                {/* Incident ID */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Incident ID</Label>
                  <p className="text-base font-mono">INC-{viewDetailsIncident.id}</p>
                </div>

                {/* Type */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Type</Label>
                  <Badge variant="outline" className="text-xs">
                    {viewDetailsIncident.incident_type.replace(/_/g, ' ')}
                  </Badge>
                </div>

                {/* Severity */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Severity</Label>
                  <Badge className={`text-xs ${
                    viewDetailsIncident.severity === 'HIGH' ? 'bg-red-100 text-red-800 border-red-200' :
                    viewDetailsIncident.severity === 'MEDIUM' ? 'bg-orange-100 text-orange-800 border-orange-200' :
                    'bg-green-100 text-green-800 border-green-200'
                  }`}>
                    {viewDetailsIncident.severity}
                  </Badge>
                </div>

                {/* Status */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Status</Label>
                  <div>{getStatusBadge(viewDetailsIncident)}</div>
                </div>

                {/* Geofence */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Geofence</Label>
                  <p className="text-base font-medium flex items-center gap-1">
                    <span className="material-icons text-sm text-indigo-600">location_on</span>
                    {viewDetailsIncident.geofence_name || `Geofence #${viewDetailsIncident.geofence}`}
                  </p>
                </div>

                {/* Officer */}
                {viewDetailsIncident.officer && (
                  <div className="space-y-1">
                    <Label className="text-sm font-medium text-muted-foreground">Assigned Officer</Label>
                    <p className="text-base font-medium">{viewDetailsIncident.officer_name || `Officer #${viewDetailsIncident.officer}`}</p>
                  </div>
                )}

                {/* Created At */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Reported</Label>
                  <p className="text-base font-medium">{formatDate(viewDetailsIncident.created_at)} at {formatTime(viewDetailsIncident.created_at)}</p>
                </div>

                {/* Resolved At */}
                {viewDetailsIncident.resolved_at && (
                  <div className="space-y-1">
                    <Label className="text-sm font-medium text-muted-foreground">Resolved</Label>
                    <p className="text-base font-medium text-green-600">{formatDate(viewDetailsIncident.resolved_at)} at {formatTime(viewDetailsIncident.resolved_at)}</p>
                  </div>
                )}

                {/* Resolved By */}
                {viewDetailsIncident.resolved_by_username && (
                  <div className="space-y-1">
                    <Label className="text-sm font-medium text-muted-foreground">Resolved By</Label>
                    <p className="text-base font-medium">{viewDetailsIncident.resolved_by_username}</p>
                  </div>
                )}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex justify-end gap-3 pt-3 border-t mt-3">
              <Button
                variant="outline"
                onClick={() => setViewDetailsIncident(null)}
              >
                <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>close</span>
                Close
              </Button>
              {!viewDetailsIncident.is_resolved && (
                <Button
                  onClick={() => {
                    handleResolve(viewDetailsIncident.id);
                    setViewDetailsIncident(null);
                  }}
                  className="bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700"
                >
                  <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>check_circle</span>
                  Mark as Resolved
                </Button>
              )}
            </div>
          </DialogContent>
        </Dialog>
      )}

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deleteIncidentId} onOpenChange={() => setDeleteIncidentId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <span className="material-icons text-red-600">warning</span>
              Delete Incident
            </AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this incident? This action cannot be undone and will permanently remove all incident data.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              className="bg-red-600 hover:bg-red-700 focus:ring-red-600"
            >
              <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>delete</span>
              Delete Incident
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
