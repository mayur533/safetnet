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
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { useSearch } from '@/lib/contexts/search-context';
import { geofencesService, type Geofence } from '@/lib/services/geofences';
import { TableLoading } from '@/components/ui/content-loading';

export function GeofencesTable() {
  const [geofences, setGeofences] = useState<Geofence[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const { searchQuery } = useSearch();
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(10);
  const [filterStatus, setFilterStatus] = useState<'all' | 'active' | 'inactive'>('all');
  const [showFilterMenu, setShowFilterMenu] = useState(false);
  const [showPerPageMenu, setShowPerPageMenu] = useState(false);
  const [viewDetailsGeofence, setViewDetailsGeofence] = useState<Geofence | null>(null);

  useEffect(() => {
    fetchGeofences();
  }, []);

  const fetchGeofences = async () => {
    try {
      setIsLoading(true);
      const data = await geofencesService.getAll();
      setGeofences(data);
    } catch (error: unknown) {
      console.error('Error fetching geofences:', error);
      toast.error('Failed to load geofences');
    } finally {
      setIsLoading(false);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };

  const getStatusBadge = (active: boolean) => {
    if (active) {
      return (
        <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 border border-green-200">
          <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
          Active
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800 border border-gray-200">
        <span className="w-2 h-2 bg-gray-500 rounded-full mr-2"></span>
        Inactive
      </span>
    );
  };

  // Filter
  let filteredGeofences = geofences.filter(
    (geo) =>
      geo.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (geo.description && geo.description.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (geo.organization_name && geo.organization_name.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  if (filterStatus !== 'all') {
    filteredGeofences = filteredGeofences.filter(
      (geo) => geo.active === (filterStatus === 'active')
    );
  }

  // Pagination
  const totalPages = Math.ceil(filteredGeofences.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedGeofences = filteredGeofences.slice(startIndex, endIndex);

  if (isLoading) {
    return (
      <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
        {/* Stats Loading */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-24 bg-muted/60 rounded-lg animate-pulse"></div>
          ))}
        </div>

        {/* Controls Loading */}
        <div className="flex items-center justify-end gap-3 mb-6 animate-pulse">
          <div className="h-10 w-32 bg-muted rounded-lg"></div>
          <div className="h-10 w-24 bg-muted rounded-lg"></div>
        </div>

        {/* Table Loading */}
        <TableLoading rows={itemsPerPage} columns={6} />

        {/* Pagination Info Loading */}
        <div className="mt-4 flex items-center justify-between animate-pulse">
          <div className="h-4 w-48 bg-muted rounded"></div>
          <div className="h-4 w-32 bg-muted rounded"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-gradient-to-br from-indigo-500 to-indigo-600 p-4 rounded-lg shadow-lg text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-indigo-100">Total Geofences</p>
              <h3 className="text-2xl font-bold mt-1">{geofences.length}</h3>
            </div>
            <span className="material-icons opacity-80" style={{ fontSize: '36px' }}>
              map
            </span>
          </div>
        </div>

        <div className="bg-gradient-to-br from-green-500 to-green-600 p-4 rounded-lg shadow-lg text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-green-100">Active Zones</p>
              <h3 className="text-2xl font-bold mt-1">
                {geofences.filter(g => g.active).length}
              </h3>
            </div>
            <span className="material-icons opacity-80" style={{ fontSize: '36px' }}>
              check_circle
            </span>
          </div>
        </div>

        <div className="bg-gradient-to-br from-gray-500 to-gray-600 p-4 rounded-lg shadow-lg text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-100">Inactive Zones</p>
              <h3 className="text-2xl font-bold mt-1">
                {geofences.filter(g => !g.active).length}
              </h3>
            </div>
            <span className="material-icons opacity-80" style={{ fontSize: '36px' }}>
              block
            </span>
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="flex items-center justify-end gap-3 mb-6">
        {/* Per Page */}
        <div className="relative">
          <button
            onClick={() => {
              setShowPerPageMenu(!showPerPageMenu);
              setShowFilterMenu(false);
            }}
            className="flex items-center gap-2 px-4 py-2 bg-background border border-border rounded-lg hover:bg-muted transition-colors"
          >
            <span className="material-icons text-lg">apps</span>
            <span className="text-sm font-medium">Per Page</span>
          </button>

          {showPerPageMenu && (
            <div className="absolute right-0 mt-2 w-48 bg-card border border-border rounded-lg shadow-lg z-10">
              <div className="p-2">
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

        {/* Filter */}
        <div className="relative">
          <button
            onClick={() => {
              setShowFilterMenu(!showFilterMenu);
              setShowPerPageMenu(false);
            }}
            className="flex items-center gap-2 px-4 py-2 bg-background border border-border rounded-lg hover:bg-muted transition-colors"
          >
            <span className="material-icons text-lg">filter_list</span>
            <span className="text-sm font-medium">Filter</span>
            {filterStatus !== 'all' && (
              <span className="w-2 h-2 bg-indigo-600 rounded-full"></span>
            )}
          </button>

          {showFilterMenu && (
            <div className="absolute right-0 mt-2 w-48 bg-card border border-border rounded-lg shadow-lg z-10">
              <div className="p-2">
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
                  All Geofences
                </button>
                <button
                  onClick={() => {
                    setFilterStatus('active');
                    setCurrentPage(1);
                    setShowFilterMenu(false);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                    filterStatus === 'active'
                      ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                      : 'hover:bg-muted'
                  }`}
                >
                  Active Only
                </button>
                <button
                  onClick={() => {
                    setFilterStatus('inactive');
                    setCurrentPage(1);
                    setShowFilterMenu(false);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                    filterStatus === 'inactive'
                      ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                      : 'hover:bg-muted'
                  }`}
                >
                  Inactive Only
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
              <TableHead className="text-muted-foreground text-sm font-semibold">Name</TableHead>
              <TableHead className="text-muted-foreground text-sm font-semibold">Description</TableHead>
              <TableHead className="text-muted-foreground text-sm font-semibold">Organization</TableHead>
              <TableHead className="text-muted-foreground text-sm font-semibold">Created By</TableHead>
              <TableHead className="text-muted-foreground text-sm font-semibold">Status</TableHead>
              <TableHead className="text-muted-foreground text-sm font-semibold text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {paginatedGeofences.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center py-12">
                  <span className="material-icons text-6xl text-muted-foreground mb-2">
                    map
                  </span>
                  <p className="text-muted-foreground">No geofences found</p>
                </TableCell>
              </TableRow>
            ) : (
              paginatedGeofences.map((geofence) => (
                <TableRow key={geofence.id} className="border-b hover:bg-muted/20 transition-colors">
                  <TableCell className="py-4 px-4">
                    <div className="flex items-center gap-2">
                      <span className="material-icons text-sm text-indigo-600">location_on</span>
                      <span className="font-medium text-sm">{geofence.name}</span>
                    </div>
                  </TableCell>
                  <TableCell className="py-4 px-4">
                    <div className="text-sm max-w-xs truncate">{geofence.description || '-'}</div>
                  </TableCell>
                  <TableCell className="py-4 px-4">
                    <div className="flex items-center gap-1 text-sm">
                      <span className="material-icons text-xs text-indigo-600">business</span>
                      {geofence.organization_name || `Org #${geofence.organization}`}
                    </div>
                  </TableCell>
                  <TableCell className="py-4 px-4">
                    <div className="text-sm">{geofence.created_by_username || 'System'}</div>
                  </TableCell>
                  <TableCell className="py-4 px-4">
                    {getStatusBadge(geofence.active)}
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
                          onClick={() => setViewDetailsGeofence(geofence)}
                        >
                          <span className="material-icons text-sm mr-2">visibility</span>
                          View Details
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

      {/* Pagination Info */}
      <div className="mt-4 flex items-center justify-between text-sm text-muted-foreground">
        <p>
          Showing {startIndex + 1}-{Math.min(endIndex, filteredGeofences.length)} of {filteredGeofences.length} geofences
          {filterStatus !== 'all' && (
            <span className="ml-2 text-indigo-600 font-medium">
              (Filtered: {filterStatus})
            </span>
          )}
        </p>
        <p>
          Page {currentPage} of {totalPages}
        </p>
      </div>

      {/* View Details Modal */}
      {viewDetailsGeofence && (
        <Dialog open={!!viewDetailsGeofence} onOpenChange={() => setViewDetailsGeofence(null)}>
          <DialogContent className="sm:max-w-[700px] bg-card/95 backdrop-blur-xl border-border/50 p-4">
            <DialogHeader>
              <DialogTitle className="text-2xl font-bold flex items-center bg-gradient-to-r from-indigo-600 to-blue-600 bg-clip-text text-transparent">
                <span className="material-icons text-indigo-600 mr-2">
                  map
                </span>
                Geofence Details
              </DialogTitle>
              <DialogDescription>
                Complete information about this security zone
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3 mt-3">
              {/* Geofence Header */}
              <div className="space-y-2 p-4 bg-gradient-to-r from-indigo-50 to-blue-50 dark:from-indigo-950/30 dark:to-blue-950/30 rounded-lg border border-indigo-200 dark:border-indigo-800">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold">{viewDetailsGeofence.name}</h3>
                  {getStatusBadge(viewDetailsGeofence.active)}
                </div>
                {viewDetailsGeofence.description && (
                  <p className="text-sm text-muted-foreground">{viewDetailsGeofence.description}</p>
                )}
              </div>

              {/* Geofence Info Grid */}
              <div className="grid grid-cols-2 gap-4">
                {/* Organization */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Organization</Label>
                  <p className="text-base font-medium flex items-center gap-1">
                    <span className="material-icons text-sm text-indigo-600">business</span>
                    {viewDetailsGeofence.organization_name || `Organization #${viewDetailsGeofence.organization}`}
                  </p>
                </div>

                {/* Created By */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Created By</Label>
                  <p className="text-base font-medium">{viewDetailsGeofence.created_by_username || 'System'}</p>
                </div>

                {/* Created At */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Created</Label>
                  <p className="text-base font-medium">{formatDate(viewDetailsGeofence.created_at)}</p>
                </div>

                {/* Updated At */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Last Updated</Label>
                  <p className="text-base font-medium">{formatDate(viewDetailsGeofence.updated_at)}</p>
                </div>

                {/* Status */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Status</Label>
                  <div>{getStatusBadge(viewDetailsGeofence.active)}</div>
                </div>

                {/* Center Point */}
                {viewDetailsGeofence.center_point && (
                  <div className="space-y-1">
                    <Label className="text-sm font-medium text-muted-foreground">Center Point</Label>
                    <p className="text-base font-mono text-xs">
                      {viewDetailsGeofence.center_point[0].toFixed(4)}, {viewDetailsGeofence.center_point[1].toFixed(4)}
                    </p>
                  </div>
                )}
              </div>

              {/* Polygon Data */}
              <div className="space-y-1 pt-2 border-t">
                <Label className="text-sm font-medium text-muted-foreground">Polygon Data</Label>
                <div className="mt-2 bg-muted/30 p-3 rounded-lg max-h-48 overflow-auto">
                  <pre className="text-xs">
                    {JSON.stringify(viewDetailsGeofence.polygon_json, null, 2)}
                  </pre>
                </div>
              </div>

              {/* Geofence ID */}
              <div className="space-y-1 pt-2 border-t">
                <Label className="text-sm font-medium text-muted-foreground">Geofence ID</Label>
                <p className="text-base font-mono text-sm">{viewDetailsGeofence.id}</p>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex justify-end gap-3 pt-3 border-t mt-3">
              <Button
                variant="outline"
                onClick={() => setViewDetailsGeofence(null)}
              >
                <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>close</span>
                Close
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}










