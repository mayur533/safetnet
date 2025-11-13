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
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { useSearch } from '@/lib/contexts/search-context';
import { TableLoading } from '@/components/ui/content-loading';
import { discountEmailsService, type DiscountEmail } from '@/lib/services/discount-emails';
import { promocodesService, type Promocode } from '@/lib/services/promocodes';

type SortField = 'created_at' | 'email' | 'status';
type SortOrder = 'asc' | 'desc';
type FilterStatus = 'all' | 'PENDING' | 'SENT';

export default function DiscountEmailsPage() {
  const [emails, setEmails] = useState<DiscountEmail[]>([]);
  const [promocodes, setPromocodes] = useState<Promocode[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSendModalOpen, setIsSendModalOpen] = useState(false);
  const [viewDetailsEmail, setViewDetailsEmail] = useState<DiscountEmail | null>(null);
  const { searchQuery } = useSearch();
  const [sortField, setSortField] = useState<SortField>('created_at');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [filterStatus, setFilterStatus] = useState<FilterStatus>('all');
  const [showFilterMenu, setShowFilterMenu] = useState(false);
  const [showSortMenu, setShowSortMenu] = useState(false);
  const [showPerPageMenu, setShowPerPageMenu] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(10);

  // Send email form
  const [sendFormData, setSendFormData] = useState({
    email: '',
    discount_code: '',
  });
  const [isSending, setIsSending] = useState(false);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      const [emailsData, promocodesData] = await Promise.all([
        discountEmailsService.getAll(),
        promocodesService.getAll()
      ]);
      setEmails(emailsData);
      setPromocodes(promocodesData.filter(p => p.is_active)); // Only active promocodes
    } catch (error) {
      console.error('Error fetching data:', error);
      toast.error('Failed to load discount emails');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSendEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!sendFormData.email || !sendFormData.discount_code) {
      toast.error('Please fill in all fields');
      return;
    }

    try {
      setIsSending(true);
      await discountEmailsService.send({
        email: sendFormData.email,
        discount_code: Number(sendFormData.discount_code),
      });
      toast.success('Discount email sent successfully');
      setIsSendModalOpen(false);
      setSendFormData({ email: '', discount_code: '' });
      fetchData(); // Refresh list
    } catch (error) {
      console.error('Send error:', error);
      toast.error('Failed to send discount email');
    } finally {
      setIsSending(false);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getStatusBadge = (status: 'PENDING' | 'SENT') => {
    if (status === 'SENT') {
      return (
        <Badge className="bg-green-100 text-green-800 border-green-200">
          <span className="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
          Sent
        </Badge>
      );
    }
    return (
      <Badge variant="outline" className="bg-yellow-100 text-yellow-800 border-yellow-200">
        <span className="w-2 h-2 bg-yellow-500 rounded-full mr-2"></span>
        Pending
      </Badge>
    );
  };

  // Filter
  let filteredEmails = emails.filter(
    (email) =>
      email.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (email.discount_code_code?.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  if (filterStatus !== 'all') {
    filteredEmails = filteredEmails.filter((email) => email.status === filterStatus);
  }

  // Sort
  filteredEmails = [...filteredEmails].sort((a, b) => {
    const aValue = a[sortField as keyof DiscountEmail];
    const bValue = b[sortField as keyof DiscountEmail];

    // Handle undefined values
    if (aValue === undefined && bValue === undefined) return 0;
    if (aValue === undefined) return 1;
    if (bValue === undefined) return -1;

    // Handle date sorting
    if (sortField === 'created_at') {
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
  const totalPages = Math.ceil(filteredEmails.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const paginatedEmails = filteredEmails.slice(startIndex, endIndex);

  const selectedPromocode = promocodes.find(p => p.id === Number(sendFormData.discount_code));

  if (isLoading) {
    return (
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between animate-pulse">
          <div>
            <div className="h-8 w-64 bg-muted rounded"></div>
            <div className="h-4 w-96 bg-muted rounded mt-2"></div>
          </div>
          <div className="h-10 w-48 bg-muted rounded"></div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-24 bg-muted rounded-lg animate-pulse"></div>
          ))}
        </div>

        {/* Table */}
        <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
          <TableLoading rows={10} columns={6} />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Discount Emails</h1>
          <p className="text-muted-foreground">Manage promotional email campaigns</p>
        </div>
        <Button
          onClick={() => setIsSendModalOpen(true)}
          className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2.5 rounded-lg font-medium shadow-lg hover:shadow-xl transition-all duration-200"
        >
          <span className="material-icons text-xl mr-2">mail</span>
          Send Discount Email
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-gradient-to-br from-indigo-500 to-indigo-600 p-4 rounded-lg shadow-lg text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-indigo-100">Total Sent</p>
              <h3 className="text-2xl font-bold mt-1">{emails.length}</h3>
            </div>
            <span className="material-icons opacity-80" style={{ fontSize: '36px' }}>
              email
            </span>
          </div>
        </div>

        <div className="bg-gradient-to-br from-yellow-500 to-yellow-600 p-4 rounded-lg shadow-lg text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-yellow-100">Pending</p>
              <h3 className="text-2xl font-bold mt-1">
                {emails.filter(e => e.status === 'PENDING').length}
              </h3>
            </div>
            <span className="material-icons opacity-80" style={{ fontSize: '36px' }}>
              schedule
            </span>
          </div>
        </div>

        <div className="bg-gradient-to-br from-green-500 to-green-600 p-4 rounded-lg shadow-lg text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-green-100">Success Rate</p>
              <h3 className="text-2xl font-bold mt-1">
                {emails.length > 0 
                  ? Math.round((emails.filter(e => e.status === 'SENT').length / emails.length) * 100)
                  : 0}%
              </h3>
            </div>
            <span className="material-icons opacity-80" style={{ fontSize: '36px' }}>
              done_all
            </span>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
        {/* Controls */}
        <div className="flex items-center justify-end gap-3 mb-6">
          {/* Per Page */}
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
                setShowSortMenu(false);
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
                  {['all', 'SENT', 'PENDING'].map((status) => (
                    <button
                      key={status}
                      onClick={() => {
                        setFilterStatus(status as FilterStatus);
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

          {/* Sort */}
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
              <div className="absolute right-0 mt-2 w-48 bg-card border border-border rounded-lg shadow-lg z-10">
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
                    <span>Date</span>
                    {sortField === 'created_at' && (
                      <span className="text-xs font-medium">{sortOrder === 'desc' ? 'Newest' : 'Oldest'}</span>
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
                <TableHead className="text-muted-foreground text-sm font-semibold">Recipient Email</TableHead>
                <TableHead className="text-muted-foreground text-sm font-semibold">Discount Code</TableHead>
                <TableHead className="text-muted-foreground text-sm font-semibold">Discount %</TableHead>
                <TableHead className="text-muted-foreground text-sm font-semibold">Status</TableHead>
                <TableHead className="text-muted-foreground text-sm font-semibold">Sent Date</TableHead>
                <TableHead className="text-muted-foreground text-sm font-semibold text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {paginatedEmails.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-12">
                    <span className="material-icons text-6xl text-muted-foreground mb-2">
                      mail_outline
                    </span>
                    <p className="text-muted-foreground">No discount emails sent yet</p>
                    <p className="text-sm text-muted-foreground mt-2">
                      Click &quot;Send Discount Email&quot; to send your first promotional email
                    </p>
                  </TableCell>
                </TableRow>
              ) : (
                paginatedEmails.map((email) => (
                  <TableRow key={email.id} className="border-b hover:bg-muted/20 transition-colors">
                    <TableCell className="py-4 px-4">
                      <div className="flex items-center gap-2">
                        <span className="material-icons text-sm text-indigo-600">person</span>
                        <span className="font-medium text-sm">{email.email}</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <Badge variant="outline" className="font-mono text-xs">
                        {email.discount_code_code || `Code #${email.discount_code}`}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <Badge className="bg-green-100 text-green-800 border-green-200 text-xs">
                        {email.discount_code_discount}% OFF
                      </Badge>
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      {getStatusBadge(email.status)}
                    </TableCell>
                    <TableCell className="py-4 px-4">
                      <div className="text-sm">{formatDate(email.created_at)}</div>
                    </TableCell>
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
                            onClick={() => setViewDetailsEmail(email)}
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
            Showing {startIndex + 1}-{Math.min(endIndex, filteredEmails.length)} of {filteredEmails.length} emails
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
              Page {currentPage} of {totalPages}
            </p>
          </div>
        </div>
      </div>

      {/* Send Email Modal */}
      {isSendModalOpen && (
        <Dialog open={isSendModalOpen} onOpenChange={setIsSendModalOpen}>
          <DialogContent className="sm:max-w-[600px] bg-card/95 backdrop-blur-xl border-border/50 p-4">
            <DialogHeader>
              <DialogTitle className="text-2xl font-bold flex items-center bg-gradient-to-r from-indigo-600 to-blue-600 bg-clip-text text-transparent">
                <span className="material-icons text-indigo-600 mr-2">
                  campaign
                </span>
                Send Discount Email
              </DialogTitle>
              <DialogDescription>
                Send a promotional email with a discount code
              </DialogDescription>
            </DialogHeader>

            <form onSubmit={handleSendEmail} className="space-y-4 mt-4">
              {/* Recipient Email */}
              <div className="space-y-2">
                <Label htmlFor="email" className="text-sm font-medium">
                  Recipient Email <span className="text-red-500">*</span>
                </Label>
                <Input
                  id="email"
                  type="email"
                  required
                  value={sendFormData.email}
                  onChange={(e) => setSendFormData({ ...sendFormData, email: e.target.value })}
                  placeholder="user@example.com"
                  className="w-full"
                />
              </div>

              {/* Select Promocode */}
              <div className="space-y-2">
                <Label htmlFor="promocode" className="text-sm font-medium">
                  Select Promocode <span className="text-red-500">*</span>
                </Label>
                <select
                  id="promocode"
                  required
                  value={sendFormData.discount_code}
                  onChange={(e) => setSendFormData({ ...sendFormData, discount_code: e.target.value })}
                  className="w-full px-3 py-2 border border-border rounded-lg bg-background focus:outline-none focus:ring-2 focus:ring-indigo-600"
                >
                  <option value="">Select a promocode...</option>
                  {promocodes.map((promo) => (
                    <option key={promo.id} value={promo.id}>
                      {promo.code} - {promo.discount_percentage}% OFF
                    </option>
                  ))}
                </select>
              </div>

              {/* Email Preview */}
              {selectedPromocode && (
                <div className="space-y-2">
                  <Label className="text-sm font-medium text-muted-foreground">Email Preview</Label>
                  <div className="bg-gradient-to-r from-indigo-50 to-blue-50 dark:from-indigo-950/30 dark:to-blue-950/30 border border-indigo-200 dark:border-indigo-800 p-4 rounded-lg">
                    <div className="space-y-3">
                      <div className="flex items-center gap-3">
                        <div className="w-12 h-12 bg-gradient-to-br from-indigo-600 to-blue-600 rounded-full flex items-center justify-center">
                          <span className="material-icons text-white">local_offer</span>
                        </div>
                        <div>
                          <h4 className="font-bold text-lg">Special Discount Just for You!</h4>
                          <p className="text-sm text-muted-foreground">SafeTNet Security Platform</p>
                        </div>
                      </div>
                      <div className="bg-white dark:bg-gray-900 p-4 rounded-lg border-2 border-dashed border-indigo-300">
                        <p className="text-center text-2xl font-bold text-indigo-600">
                          {selectedPromocode.discount_percentage}% OFF
                        </p>
                        <p className="text-center text-sm text-muted-foreground mt-1">
                          Use code: <span className="font-mono font-bold text-indigo-600">{selectedPromocode.code}</span>
                        </p>
                      </div>
                      <p className="text-xs text-muted-foreground text-center">
                        This email will be sent to: <strong>{sendFormData.email}</strong>
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex justify-end gap-3 pt-4 border-t">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setIsSendModalOpen(false);
                    setSendFormData({ email: '', discount_code: '' });
                  }}
                  disabled={isSending}
                >
                  <span className="material-icons text-sm mr-2" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>close</span>
                  Cancel
                </Button>
                <Button
                  type="submit"
                  disabled={isSending || !sendFormData.email || !sendFormData.discount_code}
                  className="bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700"
                >
                  {isSending ? (
                    <>
                      <span className="material-icons animate-spin mr-2 text-sm" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>refresh</span>
                      Sending...
                    </>
                  ) : (
                    <>
                      <span className="material-icons mr-2 text-sm" style={{ lineHeight: '0', verticalAlign: 'baseline', marginBottom: '-2px' }}>send</span>
                      Send Email
                    </>
                  )}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      )}

      {/* View Details Modal */}
      {viewDetailsEmail && (
        <Dialog open={!!viewDetailsEmail} onOpenChange={() => setViewDetailsEmail(null)}>
          <DialogContent className="sm:max-w-[600px] bg-card/95 backdrop-blur-xl border-border/50 p-4">
            <DialogHeader>
              <DialogTitle className="text-2xl font-bold flex items-center bg-gradient-to-r from-indigo-600 to-blue-600 bg-clip-text text-transparent">
                <span className="material-icons text-indigo-600 mr-2">
                  mail
                </span>
                Email Details
              </DialogTitle>
              <DialogDescription>
                Complete information about this discount email
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3 mt-3">
              {/* Email Header */}
              <div className="space-y-2 p-4 bg-gradient-to-r from-indigo-50 to-blue-50 dark:from-indigo-950/30 dark:to-blue-950/30 rounded-lg border border-indigo-200 dark:border-indigo-800">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="material-icons text-indigo-600">person</span>
                    <h3 className="text-lg font-semibold">{viewDetailsEmail.email}</h3>
                  </div>
                  {getStatusBadge(viewDetailsEmail.status)}
                </div>
              </div>

              {/* Email Info Grid */}
              <div className="grid grid-cols-2 gap-4">
                {/* Discount Code */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Discount Code</Label>
                  <Badge variant="outline" className="font-mono">
                    {viewDetailsEmail.discount_code_code || `Code #${viewDetailsEmail.discount_code}`}
                  </Badge>
                </div>

                {/* Discount Percentage */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Discount</Label>
                  <Badge className="bg-green-100 text-green-800 border-green-200">
                    {viewDetailsEmail.discount_code_discount}% OFF
                  </Badge>
                </div>

                {/* Status */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Status</Label>
                  <div>{getStatusBadge(viewDetailsEmail.status)}</div>
                </div>

                {/* Sent Date */}
                <div className="space-y-1">
                  <Label className="text-sm font-medium text-muted-foreground">Sent Date</Label>
                  <p className="text-base font-medium">{formatDate(viewDetailsEmail.created_at)}</p>
                </div>
              </div>

              {/* Email ID */}
              <div className="space-y-1 pt-2 border-t">
                <Label className="text-sm font-medium text-muted-foreground">Email ID</Label>
                <p className="text-base font-mono text-sm">{viewDetailsEmail.id}</p>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex justify-end gap-3 pt-3 border-t mt-3">
              <Button
                variant="outline"
                onClick={() => setViewDetailsEmail(null)}
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

