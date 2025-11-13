'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
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
import { CardLoading, TableLoading } from '@/components/ui/content-loading';
import { promocodesService, Promocode } from '@/lib/services/promocodes';
import { useSearch } from '@/lib/contexts/search-context';

type SortField = 'code' | 'discount_percentage' | 'expiry_date' | 'created_at';
type SortOrder = 'asc' | 'desc';

export default function PromocodesPage() {
  const router = useRouter();
  const { searchQuery } = useSearch();
  const [promocodes, setPromocodes] = useState<Promocode[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingPromocode, setEditingPromocode] = useState<Promocode | null>(null);
  const [showFilterMenu, setShowFilterMenu] = useState(false);
  const [showSortMenu, setShowSortMenu] = useState(false);
  const [showPerPageMenu, setShowPerPageMenu] = useState(false);
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [sortField, setSortField] = useState<SortField>('created_at');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(10);
  const [viewDetailsPromocode, setViewDetailsPromocode] = useState<Promocode | null>(null);
  const [deletePromocodeId, setDeletePromocodeId] = useState<number | null>(null);

  const [formData, setFormData] = useState({
    code: '',
    discount_percentage: '',
    expiry_date: '',
  });

  // Fetch promocodes on mount
  useEffect(() => {
    fetchPromocodes();
  }, []);

  const fetchPromocodes = async () => {
    try {
      setIsLoading(true);
      const data = await promocodesService.getAll();
      setPromocodes(data);
    } catch (error: unknown) {
      console.error('Failed to fetch promocodes:', error);
      toast.error('Failed to load promocodes');
    } finally {
      setIsLoading(false);
    }
  };

  // Filter by status and search
  let filteredPromocodes = promocodes.filter((promo) => {
    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      if (
        !promo.code.toLowerCase().includes(query) &&
        !promo.discount_percentage.toString().includes(query) &&
        !promo.id.toString().includes(query)
      ) {
        return false;
      }
    }
    
    const isExpired = new Date(promo.expiry_date) < new Date();
    const status = isExpired ? 'expired' : promo.is_active ? 'active' : 'inactive';
    const matchesFilter = filterStatus === 'all' || status === filterStatus;
    return matchesFilter;
  });

  // Sort
  filteredPromocodes = [...filteredPromocodes].sort((a, b) => {
    const aValue = a[sortField];
    const bValue = b[sortField];

    // Handle date sorting
    if (sortField === 'created_at' || sortField === 'expiry_date') {
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
  const totalPages = Math.ceil(filteredPromocodes.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedPromocodes = filteredPromocodes.slice(startIndex, endIndex);

  const handleAddPromocode = () => {
    setEditingPromocode(null);
    setFormData({
      code: '',
      discount_percentage: '',
      expiry_date: '',
    });
    setIsModalOpen(true);
  };

  const handleEditPromocode = (promo: Promocode) => {
    setEditingPromocode(promo);
    setFormData({
      code: promo.code,
      discount_percentage: promo.discount_percentage.toString(),
      expiry_date: promo.expiry_date.split('T')[0],
    });
    setIsModalOpen(true);
  };

  const confirmDelete = async () => {
    if (!deletePromocodeId) return;
    
    try {
      await promocodesService.delete(deletePromocodeId);
      toast.success('Promocode deleted successfully');
      setDeletePromocodeId(null);
      fetchPromocodes(); // Refresh list
    } catch (error: unknown) {
      console.error('Delete error:', error);
      toast.error(error instanceof Error ? error.message : 'Failed to delete promocode');
    }
  };

  const handleToggleStatus = async (id: number) => {
    const promo = promocodes.find(p => p.id === id);
    if (!promo) return;

    try {
      await promocodesService.update(id, { is_active: !promo.is_active });
      toast.success('Promocode status updated');
      fetchPromocodes(); // Refresh list
    } catch (error: unknown) {
      console.error('Toggle status error:', error);
      toast.error('Failed to update promocode status');
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      const expiryDateTime = new Date(formData.expiry_date);
      expiryDateTime.setHours(23, 59, 59);

      if (editingPromocode) {
        await promocodesService.update(editingPromocode.id, {
          code: formData.code,
          discount_percentage: Number(formData.discount_percentage),
          expiry_date: expiryDateTime.toISOString(),
        });
        toast.success('Promocode updated successfully');
      } else {
        await promocodesService.create({
          code: formData.code,
          discount_percentage: Number(formData.discount_percentage),
          expiry_date: expiryDateTime.toISOString(),
          is_active: true,
        });
        toast.success('Promocode created successfully');
      }

      setIsModalOpen(false);
      fetchPromocodes(); // Refresh list
    } catch (error: unknown) {
      console.error('Submit error:', error);
      try {
        const errorMessage = error instanceof Error ? error.message : 'Failed to save promocode';
        const errorObj = JSON.parse(errorMessage);
        const errorMessages = Object.entries(errorObj)
          .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`)
          .join('\n');
        toast.error(errorMessages || 'Failed to save promocode');
      } catch {
        toast.error(error instanceof Error ? error.message : 'Failed to save promocode');
      }
    }
  };

  const getStatusBadge = (promo: Promocode) => {
    const isExpired = new Date(promo.expiry_date) < new Date();
    const status = isExpired ? 'expired' : promo.is_active ? 'active' : 'inactive';

    if (status === 'active') {
      return (
        <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 border border-green-200">
          <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
          Active
        </span>
      );
    } else if (status === 'expired') {
      return (
        <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800 border border-red-200">
          <span className="w-2 h-2 bg-red-500 rounded-full mr-2"></span>
          Expired
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
            <h1 className="text-3xl font-bold">Promocodes</h1>
            <p className="text-muted-foreground mt-1">Manage discount codes and promotional offers</p>
          </div>
        </div>

        {/* Stats Loading */}
        <CardLoading count={4} />

        {/* Table Container Loading */}
        <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
          {/* Controls Loading */}
          <div className="flex items-center justify-end gap-3 mb-6 animate-pulse">
            <div className="h-10 w-32 bg-muted rounded-lg"></div>
            <div className="h-10 w-24 bg-muted rounded-lg"></div>
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
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Promocodes</h1>
          <p className="text-muted-foreground mt-1">Manage discount codes and promotional offers</p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            onClick={() => router.push('/discount-emails')}
            variant="outline"
            className="px-6 py-2.5 rounded-lg font-medium shadow hover:shadow-lg transition-all duration-200"
          >
            <span className="material-icons text-xl mr-2">campaign</span>
            Send Discount Emails
          </Button>
          <Button
            onClick={handleAddPromocode}
            className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2.5 rounded-lg font-medium shadow-lg hover:shadow-xl transition-all duration-200"
          >
            <span className="material-icons text-xl mr-2">add</span>
            Create Promocode
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-indigo-500 to-indigo-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-indigo-100">Total Codes</p>
                <h3 className="text-2xl font-bold mt-1">{promocodes.length}</h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                confirmation_number
              </span>
            </div>
          </div>
          <div className="bg-gradient-to-br from-green-500 to-green-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-green-100">Active</p>
                <h3 className="text-2xl font-bold mt-1">
                  {promocodes.filter(p => {
                    const isExpired = new Date(p.expiry_date) < new Date();
                    return !isExpired && p.is_active;
                  }).length}
                </h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                check_circle
              </span>
            </div>
          </div>
          <div className="bg-gradient-to-br from-orange-500 to-orange-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-orange-100">Valid Codes</p>
                <h3 className="text-2xl font-bold mt-1">
                  {promocodes.filter(p => p.is_valid).length}
                </h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                trending_up
              </span>
            </div>
          </div>
          <div className="bg-gradient-to-br from-red-500 to-red-600 p-4 rounded-lg shadow-lg text-white">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-red-100">Expired</p>
                <h3 className="text-2xl font-bold mt-1">
                  {promocodes.filter(p => new Date(p.expiry_date) < new Date()).length}
                </h3>
              </div>
              <span className="material-icons-outlined opacity-80" style={{ fontSize: '36px' }}>
                schedule
              </span>
            </div>
          </div>
      </div>

      {/* Table Container */}
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
                  {['all', 'active', 'inactive', 'expired'].map((status) => (
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
                  <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase">
                    Sort By
                  </div>
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
                    <span>Date Created</span>
                    {sortField === 'created_at' && (
                      <span className="text-xs font-medium">{sortOrder === 'desc' ? 'Newest' : 'Oldest'}</span>
                    )}
                  </button>
                  <button
                    onClick={() => {
                      if (sortField === 'code') {
                        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                      } else {
                        setSortField('code');
                        setSortOrder('asc');
                      }
                      setCurrentPage(1);
                    }}
                    className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                      sortField === 'code'
                        ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                        : 'hover:bg-muted'
                    }`}
                  >
                    <span>Code</span>
                    {sortField === 'code' && (
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
                  <TableHead className="text-muted-foreground text-sm font-semibold">Code</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold">Discount</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold">Usage</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold">Expiry Date</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold">Status</TableHead>
                  <TableHead className="text-muted-foreground text-sm font-semibold text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paginatedPromocodes.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-12">
                    <span className="material-icons text-6xl text-muted-foreground mb-2">
                      search_off
                    </span>
                    <p className="text-muted-foreground">No promocodes found</p>
                  </TableCell>
                </TableRow>
              ) : (
                paginatedPromocodes.map((promo) => (
                  <TableRow key={promo.id} className="border-b hover:bg-muted/20 transition-colors">
                    <TableCell className="py-4 px-4">
                      <div className="flex items-center space-x-3">
                        <div className="p-2 rounded-lg bg-indigo-100">
                          <span className="material-icons text-indigo-600" style={{ fontSize: '20px' }}>
                            confirmation_number
                          </span>
                        </div>
                        <div>
                          <div className="text-sm font-mono font-bold">{promo.code}</div>
                          <div className="text-xs text-muted-foreground">
                            Created {new Date(promo.created_at).toLocaleDateString()}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <div className="text-sm font-semibold">
                        {promo.discount_percentage}% OFF
                      </div>
                      <div className="text-xs text-muted-foreground">
                        Percentage Discount
                      </div>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <div className="text-sm">
                        {promo.is_valid ? 'Valid' : 'Expired'}
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {new Date(promo.expiry_date) > new Date() ? 'Active' : 'Inactive'}
                      </div>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <div className="text-sm">{new Date(promo.expiry_date).toLocaleDateString()}</div>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      {getStatusBadge(promo)}
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
                            onClick={() => handleEditPromocode(promo)}
                          >
                            <span className="material-icons text-sm mr-2">edit</span>
                            Edit
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            className="cursor-pointer"
                            onClick={() => handleToggleStatus(promo.id)}
                          >
                            <span className="material-icons text-sm mr-2">
                              {promo.is_active ? 'block' : 'check_circle'}
                            </span>
                            {promo.is_active ? 'Deactivate' : 'Activate'}
                          </DropdownMenuItem>
                          <DropdownMenuItem 
                            className="cursor-pointer"
                            onClick={() => setViewDetailsPromocode(promo)}
                          >
                            <span className="material-icons text-sm mr-2">visibility</span>
                            View Details
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            className="cursor-pointer text-red-600 focus:text-red-600"
                            onClick={() => setDeletePromocodeId(promo.id)}
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
            Showing {startIndex + 1}-{Math.min(endIndex, filteredPromocodes.length)} of {filteredPromocodes.length} promocodes
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

      {/* Create/Edit Promocode Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50">
          <div className="bg-card rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="px-6 py-4 border-b">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-bold">
                  {editingPromocode ? 'Edit Promocode' : 'Create New Promocode'}
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
              {/* Promocode */}
              <div>
                <label className="block text-sm font-medium mb-1">Promocode</label>
                <input
                  type="text"
                  required
                  value={formData.code}
                  onChange={(e) => setFormData({ ...formData, code: e.target.value.toUpperCase() })}
                  className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary font-mono uppercase"
                  placeholder="e.g., SAVE20"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Discount Percentage */}
                <div>
                  <label className="block text-sm font-medium mb-1">
                    Discount Percentage (%)
                  </label>
                  <input
                    type="number"
                    required
                    min="1"
                    max="100"
                    step="0.01"
                    value={formData.discount_percentage}
                    onChange={(e) => setFormData({ ...formData, discount_percentage: e.target.value })}
                    className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                    placeholder="e.g., 20"
                  />
                </div>

                {/* Expiry Date */}
                <div>
                  <label className="block text-sm font-medium mb-1">Expiry Date</label>
                  <input
                    type="date"
                    required
                    value={formData.expiry_date}
                    onChange={(e) => setFormData({ ...formData, expiry_date: e.target.value })}
                    className="w-full px-3 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary"
                  />
                </div>
              </div>

              <div className="flex justify-end space-x-3 pt-4 border-t">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 border rounded-lg hover:bg-muted/50 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
                >
                  {editingPromocode ? 'Update Promocode' : 'Create Promocode'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* View Details Modal */}
      {viewDetailsPromocode && (
        <Dialog open={!!viewDetailsPromocode} onOpenChange={() => setViewDetailsPromocode(null)}>
          <DialogContent className="sm:max-w-[600px] bg-card/95 backdrop-blur-xl border-border/50 p-4">
            <DialogHeader>
              <DialogTitle className="text-2xl font-bold flex items-center bg-gradient-to-r from-indigo-600 to-blue-600 bg-clip-text text-transparent">
                <span className="material-icons text-indigo-600 mr-2">
                  local_offer
                </span>
                Promocode Details
              </DialogTitle>
              <DialogDescription>
                Complete information about this promocode
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3 mt-3">
              {/* Promocode Info Grid */}
              <div className="grid grid-cols-2 gap-4">
                {/* Code */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Promocode</Label>
                  <p className="text-base font-medium font-mono bg-muted/30 p-2 rounded">{viewDetailsPromocode.code}</p>
                </div>

                {/* Discount Percentage */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Discount</Label>
                  <p className="text-base font-medium">{viewDetailsPromocode.discount_percentage}%</p>
                </div>

                {/* Expiry Date */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Expiry Date</Label>
                  <p className="text-base font-medium">
                    {new Date(viewDetailsPromocode.expiry_date).toLocaleDateString('en-US', {
                      year: 'numeric',
                      month: 'long',
                      day: 'numeric',
                    })}
                  </p>
                </div>

                {/* Status */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Status</Label>
                  <div className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    viewDetailsPromocode.is_active 
                      ? 'bg-green-100 text-green-800' 
                      : 'bg-gray-100 text-gray-800'
                  }`}>
                    {viewDetailsPromocode.is_active ? 'Active' : 'Inactive'}
                  </div>
                </div>

                {/* Valid Status */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Valid</Label>
                  <div className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    viewDetailsPromocode.is_valid 
                      ? 'bg-blue-100 text-blue-800' 
                      : 'bg-red-100 text-red-800'
                  }`}>
                    {viewDetailsPromocode.is_valid ? 'Valid' : 'Expired'}
                  </div>
                </div>

                {/* Created At */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Created</Label>
                  <p className="text-base font-medium">
                    {new Date(viewDetailsPromocode.created_at).toLocaleDateString('en-US', {
                      year: 'numeric',
                      month: 'long',
                      day: 'numeric',
                    })}
                  </p>
                </div>
              </div>

              {/* Promocode ID */}
              <div className="space-y-1 pt-2 border-t">
                <Label className="text-sm font-medium text-muted-foreground">Promocode ID</Label>
                <p className="text-base font-mono text-sm">{viewDetailsPromocode.id}</p>
              </div>

              {/* Last Updated */}
              <div className="space-y-1 pt-2 border-t">
                <Label className="text-sm font-medium text-muted-foreground">Last Updated</Label>
                <p className="text-base font-medium">
                  {new Date(viewDetailsPromocode.updated_at).toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric',
                  })}
                </p>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex justify-end gap-3 pt-3 border-t mt-3">
              <Button
                variant="outline"
                onClick={() => setViewDetailsPromocode(null)}
              >
                <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>close</span>
                Close
              </Button>
              <Button
                onClick={() => {
                  setViewDetailsPromocode(null);
                  handleEditPromocode(viewDetailsPromocode);
                }}
                className="bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700"
              >
                <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>edit</span>
                Edit Promocode
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      )}

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deletePromocodeId} onOpenChange={() => setDeletePromocodeId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <span className="material-icons text-red-600">warning</span>
              Delete Promocode
            </AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this promocode? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              className="bg-red-600 hover:bg-red-700 focus:ring-red-600"
            >
              <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>delete</span>
              Delete Promocode
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

