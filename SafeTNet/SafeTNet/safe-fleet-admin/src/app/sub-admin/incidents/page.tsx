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
import { Button } from '@/components/ui/button';
import { CardLoading, TableLoading } from '@/components/ui/content-loading';
import { incidentsService, type Incident as BackendIncident } from '@/lib/services/incidents';
import { useSearch } from '@/lib/contexts/search-context';

interface Incident extends BackendIncident {
  // Local interface extends backend interface
  // Map API fields to display fields
  incidentId?: string;
  type?: string;
  status?: string;
  timestamp?: string;
  priority?: string;
  geofenceName?: string;
  reportedBy?: string;
  assignedOfficer?: string;
  description?: string;
  resolvedAt?: string;
}

// Helper function to map API incident to display incident
const mapIncidentToDisplay = (incident: Incident): Incident => {
  return {
    ...incident,
    incidentId: `INC-${incident.id.toString().padStart(6, '0')}`,
    type: incident.incident_type.toLowerCase().replace('_', '-'),
    timestamp: incident.created_at,
    status: incident.is_resolved ? 'resolved' : 'open',
    priority: incident.severity.toLowerCase(),
    geofenceName: incident.geofence_name || `Geofence ${incident.geofence}`,
    reportedBy: incident.officer_name || 'System',
    assignedOfficer: incident.officer_name || 'Unassigned',
    description: incident.details,
    resolvedAt: incident.resolved_at || undefined,
  };
};

type SortField = 'id' | 'incident_type' | 'severity' | 'geofence' | 'created_at' | 'type' | 'status' | 'priority' | 'reportedBy' | 'assignedOfficer' | 'timestamp';
type SortOrder = 'asc' | 'desc';

export default function IncidentLogsPage() {
  const { searchQuery } = useSearch();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [filterGeofence, setFilterGeofence] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [dateRange, setDateRange] = useState<string>('all');
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [showFilterMenu, setShowFilterMenu] = useState(false);
  const [showSortMenu, setShowSortMenu] = useState(false);
  const [showPerPageMenu, setShowPerPageMenu] = useState(false);
  const [showDateMenu, setShowDateMenu] = useState(false);
  const [sortField, setSortField] = useState<SortField>('created_at');
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
      // Map API response to display format
      const mappedData = data.map(mapIncidentToDisplay);
      setIncidents(mappedData);
    } catch (error) {
      console.error('Failed to fetch incidents:', error);
      toast.error('Failed to load incidents');
    } finally {
      setIsLoading(false);
    }
  };

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
    const aValue = (() => {
      // Map display fields to API fields
      switch (sortField) {
        case 'id':
          return a.id;
        case 'type':
          return a.incident_type || a.type || '';
        case 'reportedBy':
          return a.officer_name || a.reportedBy || '';
        case 'geofence':
          return a.geofenceName || a.geofence_name || a.geofence;
        case 'timestamp':
        case 'created_at':
          // Return Date object for proper date comparison
          return new Date(a.timestamp || a.created_at || '');
        default:
          return String(a[sortField as keyof Incident] || '');
      }
    })();

    const bValue = (() => {
      // Map display fields to API fields
      switch (sortField) {
        case 'id':
          return b.id;
        case 'type':
          return b.incident_type || b.type || '';
        case 'reportedBy':
          return b.officer_name || b.reportedBy || '';
        case 'geofence':
          return b.geofenceName || b.geofence_name || b.geofence;
        case 'timestamp':
        case 'created_at':
          // Return Date object for proper date comparison
          return new Date(b.timestamp || b.created_at || '');
        default:
          return String(b[sortField as keyof Incident] || '');
      }
    })();

    if (sortField === 'timestamp' || sortField === 'created_at') {
      // Date comparison
      if (sortOrder === 'asc') {
        return (aValue as Date).getTime() - (bValue as Date).getTime();
      } else {
        return (bValue as Date).getTime() - (aValue as Date).getTime();
      }
    } else if (sortField === 'id') {
      // Numeric comparison for IDs
      if (sortOrder === 'asc') {
        return (aValue as number) - (bValue as number);
      } else {
        return (bValue as number) - (aValue as number);
      }
    } else {
      // String comparison
      if (sortOrder === 'asc') {
        return String(aValue).localeCompare(String(bValue));
      } else {
        return String(bValue).localeCompare(String(aValue));
      }
    }
  });

  // Pagination
  const totalPages = Math.ceil(sortedIncidents.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedIncidents = sortedIncidents.slice(startIndex, endIndex);

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

  if (isLoading) {
    return (
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Incident Logs</h1>
            <p className="text-muted-foreground mt-1">Monitor and manage security incidents</p>
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
          <h1 className="text-3xl font-bold">Incident Logs</h1>
          <p className="text-muted-foreground mt-1">Monitor and manage security incidents</p>
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
                  <button
                    onClick={() => {
                      if (sortField === 'reportedBy') {
                        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                      } else {
                        setSortField('reportedBy');
                        setSortOrder('asc');
                      }
                      setCurrentPage(1);
                    }}
                    className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                      sortField === 'reportedBy'
                        ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                        : 'hover:bg-muted'
                    }`}
                  >
                    <span>Reported By</span>
                    {sortField === 'reportedBy' && (
                      <span className="text-xs font-medium">{sortOrder === 'asc' ? 'A-Z' : 'Z-A'}</span>
                    )}
                  </button>
                  <button
                    onClick={() => {
                      if (sortField === 'geofence') {
                        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                      } else {
                        setSortField('geofence');
                        setSortOrder('asc');
                      }
                      setCurrentPage(1);
                    }}
                    className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                      sortField === 'geofence'
                        ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                        : 'hover:bg-muted'
                    }`}
                  >
                    <span>Geofence</span>
                    {sortField === 'geofence' && (
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
                  <TableHead className="text-muted-foreground text-sm font-semibold">Type</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold">Reported By</TableHead>
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
                      <span className="text-sm font-mono">{incident.incidentId}</span>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getTypeColor(incident.type || 'unknown')}`}>
                        <span className="material-icons-outlined mr-1" style={{ fontSize: '14px' }}>
                          {getTypeIcon(incident.type || 'unknown')}
                        </span>
                        {incident.type || 'Unknown'}
                      </span>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <div className="text-sm">{incident.reportedBy}</div>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <div className="flex items-center space-x-2">
                        <span className="material-icons text-sm text-indigo-600">location_on</span>
                        <span className="text-sm">{incident.geofenceName || incident.geofence_name || `Geofence ${incident.geofence}`}</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <div className="text-sm">{formatDate(incident.timestamp || incident.created_at)}</div>
                      <div className="text-xs text-muted-foreground">{formatTime(incident.timestamp || incident.created_at)}</div>
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
                            onClick={() => setSelectedIncident(incident)}
                          >
                            <span className="material-icons text-sm mr-2">visibility</span>
                            View Details
                          </DropdownMenuItem>
                          <DropdownMenuItem className="cursor-pointer">
                            <span className="material-icons text-sm mr-2">edit</span>
                            Edit
                          </DropdownMenuItem>
                          <DropdownMenuItem className="cursor-pointer text-red-600 focus:text-red-600">
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
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
          <div className="bg-card rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="px-6 py-4 border-b">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold">Incident Details</h2>
                <button
                  onClick={() => setSelectedIncident(null)}
                  className="text-muted-foreground hover:text-foreground"
                >
                  <span className="material-icons-outlined">close</span>
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-muted-foreground mb-1">Incident ID</label>
                  <p className="text-lg font-mono">{selectedIncident.incidentId}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-muted-foreground mb-1">Type</label>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getTypeColor(selectedIncident.type || 'unknown')}`}>
                    <span className="material-icons-outlined mr-1" style={{ fontSize: '14px' }}>
                      {getTypeIcon(selectedIncident.type || 'unknown')}
                    </span>
                    {selectedIncident.type || 'Unknown'}
                  </span>
                </div>
                <div>
                  <label className="block text-sm font-medium text-muted-foreground mb-1">Status</label>
                  {getStatusBadge(selectedIncident)}
                </div>
                <div>
                  <label className="block text-sm font-medium text-muted-foreground mb-1">Priority</label>
                  <p className={`text-lg font-semibold ${
                    selectedIncident.priority === 'critical' ? 'text-red-600' :
                    selectedIncident.priority === 'high' ? 'text-orange-600' :
                    selectedIncident.priority === 'medium' ? 'text-yellow-600' : 'text-green-600'
                  }`}>
                    {(selectedIncident.priority || 'unknown').toUpperCase()}
                  </p>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-muted-foreground mb-1">Title</label>
                <p className="text-lg">{selectedIncident.title}</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-muted-foreground mb-1">Description</label>
                <p>{selectedIncident.description}</p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-muted-foreground mb-1">Geofence</label>
                  <p>{selectedIncident.geofenceName || selectedIncident.geofence_name || `Geofence ${selectedIncident.geofence}`}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-muted-foreground mb-1">Reported By</label>
                  <p>{selectedIncident.reportedBy}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-muted-foreground mb-1">Assigned Officer</label>
                  <p>{selectedIncident.assignedOfficer}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-muted-foreground mb-1">Timestamp</label>
                  <p>{formatDate(selectedIncident.timestamp || selectedIncident.created_at)} {formatTime(selectedIncident.timestamp || selectedIncident.created_at)}</p>
                </div>
              </div>

              {selectedIncident.resolvedAt && (
                <div className="p-4 bg-green-50 border border-green-200 rounded-lg">
                  <label className="block text-sm font-medium text-green-800 mb-1">Resolved At</label>
                  <p className="text-green-900">{formatDate(selectedIncident.resolvedAt)} {formatTime(selectedIncident.resolvedAt)}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
