'use client';

import { useState, useEffect } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
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
import { officersService, type SecurityOfficer } from '@/lib/services/officers';
import { geofencesService, type Geofence } from '@/lib/services/geofences';
import { useSearch } from '@/lib/contexts/search-context';
import { LoadingDots } from '@/components/ui/loading-dots';

type SortField = 'name' | 'contact' | 'email' | 'created_at';
type SortOrder = 'asc' | 'desc';

export default function SecurityOfficersPage() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const { searchQuery } = useSearch();
  const [officers, setOfficers] = useState<SecurityOfficer[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingOfficer, setEditingOfficer] = useState<SecurityOfficer | null>(null);
  const [deleteOfficerId, setDeleteOfficerId] = useState<number | null>(null);
  const [showFilterMenu, setShowFilterMenu] = useState(false);
  const [showSortMenu, setShowSortMenu] = useState(false);
  const [showPerPageMenu, setShowPerPageMenu] = useState(false);
  const [sortField, setSortField] = useState<SortField>('created_at');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(10);
  
  const [formData, setFormData] = useState({
    username: '',
    name: '',
    contact: '',
    email: '',
    password: '',
    assigned_geofence: '',
  });
  const [geofences, setGeofences] = useState<Geofence[]>([]);
  const [selectedGeofencePreview, setSelectedGeofencePreview] = useState<Geofence | null>(null);

  // Fetch officers on mount
  useEffect(() => {
    fetchOfficers();
    fetchGeofences();
  }, []);

  // Open modal if URL parameter is set
  useEffect(() => {
    if (searchParams.get('add') === 'true') {
      handleAddOfficer();
      // Remove the parameter from URL
      router.replace('/sub-admin/officers');
    }
  }, [searchParams, router]);

  const fetchGeofences = async () => {
    try {
      const data = await geofencesService.getAll();
      // Filter only active geofences for better UX
      const activeGeofences = data.filter(g => g.active);
      setGeofences(activeGeofences);
    } catch (error) {
      console.error('Failed to fetch geofences:', error);
    }
  };

  const fetchOfficers = async () => {
    try {
      setIsLoading(true);
      const data = await officersService.getAll();
      setOfficers(data);
    } catch (error) {
      console.error('Failed to fetch officers:', error);
      toast.error('Failed to load security officers');
    } finally {
      setIsLoading(false);
    }
  };

  // Filter by search and status
  let filteredOfficers = officers.filter((officer) => {
    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      if (
        !officer.name?.toLowerCase().includes(query) &&
        !officer.contact?.toLowerCase().includes(query) &&
        !officer.email?.toLowerCase().includes(query) &&
        !officer.geofence_name?.toLowerCase().includes(query) &&
        !officer.id.toString().includes(query)
      ) {
        return false;
      }
    }
    
    // Status filter
    if (filterStatus === 'all') return true;
    if (filterStatus === 'Active') return officer.is_active;
    if (filterStatus === 'Inactive') return !officer.is_active;
    return true;
  });

  // Sort
  filteredOfficers = [...filteredOfficers].sort((a, b) => {
    const aValue = a[sortField];
    const bValue = b[sortField];

    // Handle undefined/null values
    if (!aValue && !bValue) return 0;
    if (!aValue) return 1;
    if (!bValue) return -1;

    if (sortOrder === 'asc') {
      return aValue > bValue ? 1 : -1;
    } else {
      return aValue < bValue ? 1 : -1;
    }
  });

  // Pagination
  const totalPages = Math.ceil(filteredOfficers.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedOfficers = filteredOfficers.slice(startIndex, endIndex);

  const handleAddOfficer = () => {
    setEditingOfficer(null);
    setFormData({
      username: '',
      name: '',
      contact: '',
      email: '',
      password: '',
      assigned_geofence: '',
    });
    setSelectedGeofencePreview(null);
    setIsModalOpen(true);
  };

  const handleEditOfficer = (officer: SecurityOfficer) => {
    setEditingOfficer(officer);
    setFormData({
      username: officer.username || '',
      name: officer.name,
      contact: officer.contact,
      email: officer.email || '',
      password: '', // Don't populate password when editing
      assigned_geofence: officer.assigned_geofence?.toString() || '',
    });
    // Set the preview for the assigned geofence
    const geofence = geofences.find(g => g.id === officer.assigned_geofence);
    setSelectedGeofencePreview(geofence || null);
    setIsModalOpen(true);
  };

  const handleGeofenceChange = (geofenceId: string) => {
    setFormData({ ...formData, assigned_geofence: geofenceId });
    // Update preview
    const geofence = geofences.find(g => g.id.toString() === geofenceId);
    setSelectedGeofencePreview(geofence || null);
  };

  const handleDeleteOfficer = (id: number) => {
    setDeleteOfficerId(id);
  };

  const confirmDeleteOfficer = async () => {
    if (!deleteOfficerId) return;
    
    try {
      await officersService.delete(deleteOfficerId);
      toast.success('Officer deleted successfully');
      setDeleteOfficerId(null);
      fetchOfficers(); // Refresh list
    } catch (error) {
      console.error('Delete error:', error);
      toast.error('Failed to delete officer');
      setDeleteOfficerId(null);
    }
  };

  const handleToggleStatus = async (id: number) => {
    const officer = officers.find(o => o.id === id);
    if (!officer) return;

    try {
      await officersService.update(id, { is_active: !officer.is_active });
      toast.success('Officer status updated');
      fetchOfficers(); // Refresh list
    } catch (error) {
      console.error('Toggle status error:', error);
      toast.error('Failed to update officer status');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!formData.name || !formData.contact) {
      toast.error('Name and contact are required');
      return;
    }

    if (!editingOfficer && !formData.username) {
      toast.error('Username is required');
      return;
    }

    if (isSubmitting) {
      return; // Prevent double submission
    }

    setIsSubmitting(true);

    try {
      if (editingOfficer) {
        // Update existing officer
        await officersService.update(editingOfficer.id, {
          username: formData.username || undefined,
          name: formData.name,
          contact: formData.contact,
          email: formData.email || undefined,
          assigned_geofence: formData.assigned_geofence ? parseInt(formData.assigned_geofence) : undefined,
        });
        toast.success('Officer updated successfully');
      } else {
        // Validate required fields for new officers
        if (!formData.username || !formData.username.trim()) {
          toast.error('Username is required');
          setIsSubmitting(false);
          return;
        }
        if (!formData.password || formData.password.length < 6) {
          toast.error('Password is required and must be at least 6 characters');
          setIsSubmitting(false);
          return;
        }
        
        // Create new officer
        await officersService.create({
          username: formData.username,
          name: formData.name,
          contact: formData.contact,
          password: formData.password,
          email: formData.email || undefined,
          assigned_geofence: formData.assigned_geofence ? parseInt(formData.assigned_geofence) : undefined,
        });
        toast.success('Officer created successfully');
      }
      
      setIsModalOpen(false);
      fetchOfficers(); // Refresh list
    } catch (error) {
      console.error('Submit error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Failed to save officer';
      toast.error(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  const getStatusBadge = (is_active: boolean) => {
    if (is_active) {
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

  if (isLoading) {
    return (
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold">Security Officers</h1>
            <p className="text-muted-foreground mt-1">Manage your security team</p>
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
            <TableLoading rows={10} columns={6} />
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
          <h1 className="text-3xl font-bold">Security Officers</h1>
          <p className="text-muted-foreground mt-1">Manage your security team</p>
        </div>
        <Button
          onClick={handleAddOfficer}
          className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2.5 rounded-lg font-medium shadow-lg hover:shadow-xl transition-all duration-200"
        >
          <span className="material-icons text-xl mr-2">person_add</span>
          Add Officer
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-blue-500 to-blue-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-blue-100">Total Officers</p>
                <h3 className="text-2xl font-bold mt-1">{officers.length}</h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                security
              </span>
            </div>
          </div>
          <div className="bg-gradient-to-br from-green-500 to-green-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-green-100">Active</p>
                <h3 className="text-2xl font-bold mt-1">
                  {officers.filter(o => o.is_active).length}
                </h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                check_circle
              </span>
            </div>
          </div>
          <div className="bg-gradient-to-br from-gray-500 to-gray-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-100">Inactive</p>
                <h3 className="text-2xl font-bold mt-1">
                  {officers.filter(o => !o.is_active).length}
                </h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                cancel
              </span>
            </div>
          </div>
          <div className="bg-gradient-to-br from-purple-500 to-purple-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-purple-100">On Duty</p>
                <h3 className="text-2xl font-bold mt-1">
                  {Math.floor(officers.filter(o => o.is_active).length * 0.75)}
                </h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                badge
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
              {filterStatus !== 'all' && (
                <span className="w-2 h-2 bg-indigo-600 rounded-full"></span>
              )}
            </button>

            {showFilterMenu && (
              <div className="absolute right-0 mt-2 w-48 bg-card border border-border rounded-lg shadow-lg z-10">
                <div className="p-2">
                  {['all', 'Active', 'Inactive'].map((status) => (
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
                      {status === 'all' ? 'All Status' : status}
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
                      if (sortField === 'created_at') {
                        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                      } else {
                        setSortField('created_at');
                        setSortOrder('desc');
                      }
                      setCurrentPage(1);
                    }}
                    className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                      sortField === 'created_at'
                        ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                        : 'hover:bg-muted'
                    }`}
                  >
                    <span>Date Joined</span>
                    {sortField === 'created_at' && (
                      <span className="text-xs font-medium">{sortOrder === 'desc' ? 'Newest' : 'Oldest'}</span>
                    )}
                  </button>
                  <button
                    onClick={() => {
                      if (sortField === 'name') {
                        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                      } else {
                        setSortField('name');
                        setSortOrder('asc');
                      }
                      setCurrentPage(1);
                    }}
                    className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                      sortField === 'name'
                        ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                        : 'hover:bg-muted'
                    }`}
                  >
                    <span>Name</span>
                    {sortField === 'name' && (
                      <span className="text-xs font-medium">{sortOrder === 'asc' ? 'A-Z' : 'Z-A'}</span>
                    )}
                  </button>
                  <button
                    onClick={() => {
                      if (sortField === 'email') {
                        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                      } else {
                        setSortField('email');
                        setSortOrder('asc');
                      }
                      setCurrentPage(1);
                    }}
                    className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                      sortField === 'email'
                        ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                        : 'hover:bg-muted'
                    }`}
                  >
                    <span>Email</span>
                    {sortField === 'email' && (
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
                  <TableHead className="text-muted-foreground text-sm font-semibold">Officer Name</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold">Username</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold">Assigned Geofence</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold">Contact</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold">Status</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paginatedOfficers.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-12">
                    <span className="material-icons text-6xl text-muted-foreground mb-2">
                      search_off
                    </span>
                    <p className="text-muted-foreground">No officers found</p>
                  </TableCell>
                </TableRow>
              ) : (
                paginatedOfficers.map((officer) => (
                  <TableRow key={officer.id} className="border-b hover:bg-muted/20 transition-colors">
                    <TableCell className="py-4 px-4">
                      <div className="flex items-center space-x-3">
                        <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center text-white font-semibold">
                          {officer.name.charAt(0).toUpperCase()}
                        </div>
                        <div>
                          <div className="text-sm font-medium">{officer.name}</div>
                          <div className="text-xs text-muted-foreground">
                            Joined {new Date(officer.created_at).toLocaleDateString()}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <div className="text-sm font-medium">{officer.username || `SO-${officer.id.toString().padStart(3, '0')}`}</div>
                      {officer.username && (
                        <div className="text-xs text-muted-foreground">ID: {officer.id}</div>
                      )}
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <div className="flex items-center space-x-2">
                        <span className="material-icons text-sm text-indigo-600">location_on</span>
                        <span className="text-sm">{officer.assigned_geofence || 'Not Assigned'}</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <div className="text-sm">{officer.contact}</div>
                      <div className="text-xs text-muted-foreground">{officer.email || 'N/A'}</div>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      {getStatusBadge(officer.is_active)}
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
                            onClick={() => handleEditOfficer(officer)}
                          >
                            <span className="material-icons text-sm mr-2">edit</span>
                            Edit
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            className="cursor-pointer"
                            onClick={() => handleToggleStatus(officer.id)}
                          >
                            <span className="material-icons text-sm mr-2">
                              {officer.is_active ? 'block' : 'check_circle'}
                            </span>
                            {officer.is_active ? 'Deactivate' : 'Activate'}
                          </DropdownMenuItem>
                          <DropdownMenuItem className="cursor-pointer text-red-600 focus:text-red-600" onClick={() => handleDeleteOfficer(officer.id)}>
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
            Showing {startIndex + 1}-{Math.min(endIndex, filteredOfficers.length)} of {filteredOfficers.length} officers
            {filterStatus !== 'all' && (
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

      {/* Add/Edit Officer Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
          <div className="bg-card rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="px-6 py-4 border-b">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold">
                  {editingOfficer ? 'Edit Officer' : 'Add New Officer'}
                </h2>
                <button
                  onClick={() => setIsModalOpen(false)}
                  className="text-muted-foreground hover:text-foreground"
                >
                  <span className="material-icons-outlined">close</span>
                </button>
              </div>
            </div>

            <form onSubmit={handleSubmit} className="p-6 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Username *</label>
                  <input
                    type="text"
                    required={!editingOfficer}
                    value={formData.username}
                    onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                    className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                    placeholder="Enter unique username"
                    disabled={!!editingOfficer}
                  />
                  {editingOfficer && (
                    <p className="text-xs text-muted-foreground mt-1">Username cannot be changed after creation</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium mb-1">Officer Name *</label>
                  <input
                    type="text"
                    required
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                    placeholder="Enter full name"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium mb-1">Contact Number</label>
                  <input
                    type="tel"
                    required
                    value={formData.contact}
                    onChange={(e) => setFormData({ ...formData, contact: e.target.value })}
                    className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                    placeholder="+1 234-567-8900"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium mb-1">Email Address</label>
                  <input
                    type="email"
                    required
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                    placeholder="officer@security.com"
                  />
                </div>

                {!editingOfficer && (
                  <div>
                    <label className="block text-sm font-medium mb-1">Password *</label>
                    <input
                      type="password"
                      required={!editingOfficer}
                      value={formData.password}
                      onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                      className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                      placeholder="Minimum 6 characters"
                      minLength={6}
                    />
                  </div>
                )}

                <div className="md:col-span-2">
                  <label className="block text-sm font-medium mb-1">Assigned Geofence</label>
                  <select
                    value={formData.assigned_geofence}
                    onChange={(e) => handleGeofenceChange(e.target.value)}
                    className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                  >
                    <option value="">Select Geofence (Optional)</option>
                    {geofences.map((geofence) => (
                      <option key={geofence.id} value={geofence.id.toString()}>
                        {geofence.name} (ID: {geofence.id})
                      </option>
                    ))}
                  </select>
                  
                  {/* Geofence Preview */}
                  {selectedGeofencePreview && (
                    <div className="mt-3 p-4 bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800 rounded-lg">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="material-icons text-blue-600 dark:text-blue-400 text-lg">location_on</span>
                        <h4 className="font-semibold text-blue-900 dark:text-blue-100">Geofence Preview</h4>
                      </div>
                      <div className="space-y-1 text-sm">
                        <p><span className="font-medium">Name:</span> {selectedGeofencePreview.name}</p>
                        <p><span className="font-medium">ID:</span> {selectedGeofencePreview.id}</p>
                        {selectedGeofencePreview.description && (
                          <p><span className="font-medium">Description:</span> {selectedGeofencePreview.description}</p>
                        )}
                        <p>
                          <span className="font-medium">Status:</span>{' '}
                          <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${
                            selectedGeofencePreview.active 
                              ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-100' 
                              : 'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-100'
                          }`}>
                            {selectedGeofencePreview.active ? 'Active' : 'Inactive'}
                          </span>
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex justify-end space-x-3 pt-4 border-t">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  disabled={isSubmitting}
                  className="px-4 py-2 border rounded-lg hover:bg-muted/50 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                >
                  {isSubmitting ? (
                    <>
                      <LoadingDots />
                      <span>{editingOfficer ? 'Updating' : 'Creating'}</span>
                    </>
                  ) : (
                    editingOfficer ? 'Update Officer' : 'Add Officer'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deleteOfficerId} onOpenChange={() => setDeleteOfficerId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <span className="material-icons text-red-600">warning</span>
              Delete Security Officer
            </AlertDialogTitle>
            <AlertDialogDescription className="pt-2">
              Are you sure you want to delete this security officer? This action cannot be undone and will permanently remove the officer and all associated data.
              {deleteOfficerId && (
                <span className="block mt-2 font-semibold text-foreground">
                  Officer: {officers.find(o => o.id === deleteOfficerId)?.name || 'Unknown'}
                </span>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => setDeleteOfficerId(null)}>
              Cancel
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDeleteOfficer}
              className="bg-red-600 hover:bg-red-700 text-white"
            >
              <span className="material-icons text-sm mr-2">delete</span>
              Delete Officer
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
