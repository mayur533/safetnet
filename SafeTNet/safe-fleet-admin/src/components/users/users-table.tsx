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
import { useSearch } from '@/lib/contexts/search-context';
import { usersService, type User } from '@/lib/services/users';
import { CardLoading, TableLoading } from '@/components/ui/content-loading';

interface UsersTableProps {
  onEditUser: (userId: number) => void;
  refreshTrigger?: number;
}

type SortField = 'username' | 'email' | 'date_joined';
type SortOrder = 'asc' | 'desc';
type FilterRole = 'all' | 'SUPER_ADMIN' | 'SUB_ADMIN' | 'USER';
type FilterStatus = 'all' | 'active' | 'inactive';

export function UsersTable({ onEditUser, refreshTrigger = 0 }: UsersTableProps) {
  const router = useRouter();
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const { searchQuery } = useSearch();
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(10);
  const [sortField, setSortField] = useState<SortField>('date_joined');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [filterRole, setFilterRole] = useState<FilterRole>('all');
  const [filterStatus, setFilterStatus] = useState<FilterStatus>('all');
  const [showPaginationMenu, setShowPaginationMenu] = useState(false);
  const [showFilterMenu, setShowFilterMenu] = useState(false);
  const [showSortMenu, setShowSortMenu] = useState(false);
  const [viewDetailsUser, setViewDetailsUser] = useState<User | null>(null);
  const [deleteUserId, setDeleteUserId] = useState<number | null>(null);

  // Fetch users on mount and when refreshTrigger changes
  useEffect(() => {
    fetchUsers();
  }, [refreshTrigger]);

  const fetchUsers = async () => {
    try {
      setIsLoading(true);
      const data = await usersService.getAll();
      
      // Filter to show only regular USER role (exclude SUPER_ADMIN and SUB_ADMIN)
      const regularUsers = data.filter(user => 
        user.role !== 'SUPER_ADMIN' && 
        user.role !== 'SUB_ADMIN' && 
        user.role !== 'SUPER ADMIN' && 
        user.role !== 'SUB ADMIN'
      );
      setUsers(regularUsers);
    } catch (error) {
      console.error('Failed to fetch users:', error);
      toast.error('Failed to load users');
    } finally {
      setIsLoading(false);
    }
  };

  // Filter by search
  let filteredUsers = users.filter(
    (user) =>
      user.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
      user.role.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Filter by role
  if (filterRole !== 'all') {
    filteredUsers = filteredUsers.filter((user) => user.role === filterRole);
  }

  // Filter by status
  if (filterStatus !== 'all') {
    filteredUsers = filteredUsers.filter((user) => {
      const isActive = user.is_active;
      return filterStatus === 'active' ? isActive : !isActive;
    });
  }

  // Sort
  filteredUsers = [...filteredUsers].sort((a, b) => {
    const aValue = a[sortField];
    const bValue = b[sortField];

    // Handle date_joined sorting differently
    if (sortField === 'date_joined') {
      if (sortOrder === 'asc') {
        return new Date(aValue).getTime() - new Date(bValue).getTime();
      } else {
        return new Date(bValue).getTime() - new Date(aValue).getTime();
      }
    }

    // Handle string sorting
    if (sortOrder === 'asc') {
      return String(aValue || '').localeCompare(String(bValue || ''));
    } else {
      return String(bValue || '').localeCompare(String(aValue || ''));
    }
  });

  // Pagination
  const totalPages = Math.ceil(filteredUsers.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedUsers = filteredUsers.slice(startIndex, endIndex);

  const confirmDelete = async () => {
    if (!deleteUserId) return;
    
    try {
      await usersService.delete(deleteUserId);
      toast.success('User deleted successfully');
      setDeleteUserId(null);
      fetchUsers(); // Refresh list
    } catch (error: unknown) {
      console.error('Delete error:', error);
      toast.error(error instanceof Error ? error.message : 'Failed to delete user');
    }
  };

  const handleToggleStatus = async (id: number) => {
    const user = users.find(u => u.id === id);
    if (!user) return;

    try {
      await usersService.update(id, { is_active: !user.is_active });
      toast.success('User status updated');
      fetchUsers(); // Refresh list
    } catch (error: unknown) {
      console.error('Toggle status error:', error);
      toast.error('Failed to update user status');
    }
  };

  const getRoleBadge = (role: string) => {
    const normalizedRole = role.toUpperCase().replace(/_/g, ' ');
    let badgeClass = '';
    let displayRole = '';

    if (normalizedRole === 'SUPER ADMIN' || normalizedRole === 'ADMIN') {
      badgeClass = 'bg-purple-100 text-purple-800 dark:bg-purple-900/50 dark:text-purple-300';
      displayRole = 'Admin';
    } else if (normalizedRole === 'SUB ADMIN') {
      badgeClass = 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900/50 dark:text-indigo-300';
      displayRole = 'Sub-Admin';
    } else {
      badgeClass = 'bg-gray-100 text-gray-800 dark:bg-gray-700/50 dark:text-gray-300';
      displayRole = 'User';
    }

    return (
      <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${badgeClass}`}>
        {displayRole}
      </span>
    );
  };

  const getStatusBadge = (status: 'active' | 'inactive') => {
    if (status === 'active') {
      return (
        <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300">
          <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
          Active
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700/50 dark:text-gray-300">
        <span className="w-2 h-2 bg-gray-500 rounded-full mr-2"></span>
        Inactive
      </span>
    );
  };

  if (isLoading) {
    return (
      <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
        {/* Stats Loading */}
        <CardLoading count={4} className="mb-6" />

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
    );
  }

  return (
    <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-gradient-to-br from-purple-500 to-indigo-600 p-4 rounded-xl text-white shadow-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm opacity-90">Total Users</p>
              <p className="text-2xl font-bold mt-1">{users.length}</p>
            </div>
            <span className="material-icons text-4xl opacity-80">people</span>
          </div>
        </div>
        <div className="bg-gradient-to-br from-green-500 to-teal-600 p-4 rounded-xl text-white shadow-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm opacity-90">Active Users</p>
              <p className="text-2xl font-bold mt-1">
                {users.filter((u) => u.is_active === true).length}
              </p>
            </div>
            <span className="material-icons text-4xl opacity-80">check_circle</span>
          </div>
        </div>
        <div className="bg-gradient-to-br from-blue-500 to-cyan-600 p-4 rounded-xl text-white shadow-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm opacity-90">Inactive Users</p>
              <p className="text-2xl font-bold mt-1">
                {users.filter((u) => u.is_active === false).length}
              </p>
            </div>
            <span className="material-icons text-4xl opacity-80">block</span>
          </div>
        </div>
        <div className="bg-gradient-to-br from-orange-500 to-red-600 p-4 rounded-xl text-white shadow-lg">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm opacity-90">Organizations</p>
              <p className="text-2xl font-bold mt-1">
                {new Set(users.map((u) => u.organization?.id).filter(Boolean)).size}
              </p>
            </div>
            <span className="material-icons text-4xl opacity-80">business</span>
          </div>
        </div>
      </div>

      {/* Controls */}
      <div className="flex items-center justify-end gap-3 mb-6">
        {/* Pagination Button */}
        <div className="relative">
          <button
            onClick={() => {
              setShowPaginationMenu(!showPaginationMenu);
              setShowFilterMenu(false);
              setShowSortMenu(false);
            }}
            className="flex items-center gap-2 px-4 py-2 bg-background border border-border rounded-lg hover:bg-muted transition-colors"
          >
            <span className="material-icons text-lg">apps</span>
            <span className="text-sm font-medium">Pagination</span>
          </button>

          {showPaginationMenu && (
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
                      setShowPaginationMenu(false);
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
              setShowPaginationMenu(false);
              setShowSortMenu(false);
            }}
            className="flex items-center gap-2 px-4 py-2 bg-background border border-border rounded-lg hover:bg-muted transition-colors"
          >
            <span className="material-icons text-lg">filter_list</span>
            <span className="text-sm font-medium">Filter</span>
            {(filterRole !== 'all' || filterStatus !== 'all') && (
              <span className="w-2 h-2 bg-indigo-600 rounded-full"></span>
            )}
          </button>

          {showFilterMenu && (
            <div className="absolute right-0 mt-2 w-56 bg-card border border-border rounded-lg shadow-lg z-10">
              <div className="p-2">
                <button
                  onClick={() => {
                    setFilterStatus('all');
                    setFilterRole('all');
                    setCurrentPage(1);
                    setShowFilterMenu(false);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors ${
                    filterStatus === 'all' && filterRole === 'all'
                      ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                      : 'hover:bg-muted'
                  }`}
                >
                  All
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
                  Active
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
                  Inactive
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Sort Button */}
        <div className="relative">
          <button
            onClick={() => {
              setShowSortMenu(!showSortMenu);
              setShowPaginationMenu(false);
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
                    if (sortField === 'username') {
                      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                    } else {
                      setSortField('username');
                      setSortOrder('asc');
                    }
                    setCurrentPage(1);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                    sortField === 'username'
                      ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                      : 'hover:bg-muted'
                  }`}
                >
                  <span>Name</span>
                  {sortField === 'username' && (
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
                <button
                  onClick={() => {
                    if (sortField === 'date_joined') {
                      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                    } else {
                      setSortField('date_joined');
                      setSortOrder('desc');
                    }
                    setCurrentPage(1);
                  }}
                  className={`w-full text-left px-3 py-2 rounded-md text-sm transition-colors flex items-center justify-between ${
                    sortField === 'date_joined'
                      ? 'bg-indigo-100 text-indigo-900 dark:bg-indigo-900/20 dark:text-indigo-100'
                      : 'hover:bg-muted'
                  }`}
                >
                  <span>Last Added</span>
                  {sortField === 'date_joined' && (
                    <span className="text-xs font-medium">{sortOrder === 'desc' ? 'Newest' : 'Oldest'}</span>
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
                <TableHead className="text-muted-foreground text-sm font-semibold">Name</TableHead>
                <TableHead className="text-muted-foreground text-sm font-semibold">Email</TableHead>
                <TableHead className="text-muted-foreground text-sm font-semibold">Status</TableHead>
                <TableHead className="text-muted-foreground text-sm font-semibold text-right">
                  Actions
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {paginatedUsers.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="text-center py-12">
                  <span className="material-icons text-6xl text-muted-foreground mb-2">
                    search_off
                  </span>
                  <p className="text-muted-foreground">No users found</p>
                </TableCell>
              </TableRow>
            ) : (
              paginatedUsers.map((user) => (
                <TableRow
                  key={user.id}
                  className="border-b hover:bg-muted/20 transition-colors"
                >
                  <TableCell className="py-4 px-4">
                    <div className="flex items-center space-x-3">
                      <div className="w-10 h-10 rounded-full bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center text-white font-semibold shadow-lg">
                        {user.username.charAt(0).toUpperCase()}
                      </div>
                      <div className="font-medium text-sm">{user.username}</div>
                    </div>
                  </TableCell>
                  <TableCell className="py-4 px-4">
                    <div className="text-sm text-muted-foreground">{user.email}</div>
                  </TableCell>
                  <TableCell className="py-4 px-4">{getStatusBadge(user.is_active ? 'active' : 'inactive')}</TableCell>
                  <TableCell className="py-4 px-4 text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 w-8 p-0 hover:bg-muted"
                        >
                          <span className="material-icons text-lg">more_vert</span>
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end" className="w-48">
                        <DropdownMenuItem 
                          className="cursor-pointer"
                          onClick={() => onEditUser(user.id)}
                        >
                          <span className="material-icons text-sm mr-2">edit</span>
                          Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          className="cursor-pointer"
                          onClick={() => handleToggleStatus(user.id)}
                        >
                          <span className="material-icons text-sm mr-2">
                            {user.is_active ? 'block' : 'check_circle'}
                          </span>
                          {user.is_active ? 'Deactivate' : 'Activate'}
                        </DropdownMenuItem>
                        <DropdownMenuItem 
                          className="cursor-pointer"
                          onClick={() => setViewDetailsUser(user)}
                        >
                          <span className="material-icons text-sm mr-2">visibility</span>
                          View Details
                        </DropdownMenuItem>
                        <DropdownMenuItem 
                          className="cursor-pointer text-red-600 focus:text-red-600"
                          onClick={() => setDeleteUserId(user.id)}
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

      {/* Pagination Info */}
      <div className="mt-4 flex items-center justify-between text-sm text-muted-foreground">
        <p>
          Showing {startIndex + 1}-{Math.min(endIndex, filteredUsers.length)} of {filteredUsers.length} users
          {(filterRole !== 'all' || filterStatus !== 'all') && (
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

      {/* View Details Modal */}
      {viewDetailsUser && (
        <Dialog open={!!viewDetailsUser} onOpenChange={() => setViewDetailsUser(null)}>
          <DialogContent className="sm:max-w-[600px] bg-card/95 backdrop-blur-xl border-border/50 p-4">
            <DialogHeader>
              <DialogTitle className="text-2xl font-bold flex items-center bg-gradient-to-r from-indigo-600 to-blue-600 bg-clip-text text-transparent">
                <span className="material-icons text-indigo-600 mr-2">
                  person
                </span>
                User Details
              </DialogTitle>
              <DialogDescription>
                Complete information about this user
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3 mt-3">
              {/* User Info Grid */}
              <div className="grid grid-cols-2 gap-4">
                {/* Username */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Username</Label>
                  <p className="text-base font-medium">{viewDetailsUser.username}</p>
                </div>

                {/* Email */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Email</Label>
                  <p className="text-base font-medium">{viewDetailsUser.email}</p>
                </div>

                {/* First Name */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">First Name</Label>
                  <p className="text-base font-medium">{viewDetailsUser.first_name || 'Not set'}</p>
                </div>

                {/* Last Name */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Last Name</Label>
                  <p className="text-base font-medium">{viewDetailsUser.last_name || 'Not set'}</p>
                </div>

                {/* Role */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Role</Label>
                  <div>{getRoleBadge(viewDetailsUser.role)}</div>
                </div>

                {/* Status */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Status</Label>
                   <div>{getStatusBadge(viewDetailsUser.is_active ? 'active' : 'inactive')}</div>
                </div>

                {/* Date Joined */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Date Joined</Label>
                  <p className="text-base font-medium">
                    {new Date(viewDetailsUser.date_joined).toLocaleDateString('en-US', {
                      year: 'numeric',
                      month: 'long',
                      day: 'numeric',
                    })}
                  </p>
                </div>

                {/* Last Login */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Last Login</Label>
                  <p className="text-base font-medium">
                    {viewDetailsUser.last_login 
                      ? new Date(viewDetailsUser.last_login).toLocaleDateString('en-US', {
                          year: 'numeric',
                          month: 'long',
                          day: 'numeric',
                        })
                      : 'Never'
                    }
                  </p>
                </div>
              </div>

              {/* Organization */}
              {viewDetailsUser.organization && (
                <div className="space-y-1 pt-2 border-t">
                  <Label className="text-sm font-medium text-muted-foreground">Organization</Label>
                  <p className="text-base font-medium">{viewDetailsUser.organization.name}</p>
                </div>
              )}

              {/* User ID */}
              <div className="space-y-1 pt-2 border-t">
                <Label className="text-sm font-medium text-muted-foreground">User ID</Label>
                <p className="text-base font-mono text-sm">{viewDetailsUser.id}</p>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="space-y-3 pt-3 border-t mt-3">
              {/* Additional Info Buttons */}
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  onClick={() => router.push(`/users/${viewDetailsUser.id}/replies`)}
                  className="flex-1"
                >
                  <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>forum</span>
                  User Replies
                </Button>
                <Button
                  variant="outline"
                  onClick={() => router.push(`/users/${viewDetailsUser.id}/details`)}
                  className="flex-1"
                >
                  <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>info</span>
                  User Details
                </Button>
              </div>
              
              {/* Main Action Buttons */}
              <div className="flex justify-end gap-3">
                <Button
                  variant="outline"
                  onClick={() => setViewDetailsUser(null)}
                >
                  <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>close</span>
                  Close
                </Button>
                <Button
                  onClick={() => {
                    setViewDetailsUser(null);
                    onEditUser(viewDetailsUser.id);
                  }}
                  className="bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700"
                >
                  <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>edit</span>
                  Edit User
                </Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      )}

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={!!deleteUserId} onOpenChange={() => setDeleteUserId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              <span className="material-icons text-red-600">warning</span>
              Delete User
            </AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete this user? This action cannot be undone and will permanently remove the user and all associated data.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              className="bg-red-600 hover:bg-red-700 focus:ring-red-600"
            >
              <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>delete</span>
              Delete User
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}



