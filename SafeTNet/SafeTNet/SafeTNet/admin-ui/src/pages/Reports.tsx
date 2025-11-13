import React, { useState, useEffect } from 'react';
import {
  Container,
  AppBar,
  Toolbar,
  Typography,
  Button,
  Box,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Pagination,
  Alert,
  CircularProgress,
  Grid,
  Card,
  CardContent,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Search as SearchIcon,
  Download as DownloadIcon,
  Add as AddIcon,
  Description as ReportIcon,
} from '@mui/icons-material';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { useAuth } from '../contexts/AuthContext';
import { reportService } from '../services/reportService';
import { GlobalReport, ReportCreateRequest } from '../types';

const Reports: React.FC = () => {
  const { user, logout } = useAuth();
  const [reports, setReports] = useState<GlobalReport[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState('');
  const [filterGenerated, setFilterGenerated] = useState<boolean | null>(null);
  
  // Dialog states
  const [openDialog, setOpenDialog] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [formData, setFormData] = useState<ReportCreateRequest>({
    report_type: 'GEOFENCE_ANALYTICS',
    title: '',
    description: '',
    date_range_start: new Date().toISOString(),
    date_range_end: new Date().toISOString(),
  });

  // Check if user has access
  const hasAccess = user?.role === 'SUPER_ADMIN';

  useEffect(() => {
    if (hasAccess) {
      fetchReports();
    }
  }, [hasAccess, page, search, filterType, filterGenerated]);

  const fetchReports = async () => {
    setLoading(true);
    setError('');
    try {
      const params: any = {
        page,
        page_size: 10,
      };
      
      if (search) params.search = search;
      if (filterType) params.report_type = filterType;
      if (filterGenerated !== null) params.is_generated = filterGenerated;

      const response = await reportService.getReports(params);
      setReports(response.results);
      setTotalCount(response.count);
      setTotalPages(Math.ceil(response.count / 10));
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to fetch Reports');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = () => {
    setFormData({
      report_type: 'GEOFENCE_ANALYTICS',
      title: '',
      description: '',
      date_range_start: new Date().toISOString(),
      date_range_end: new Date().toISOString(),
    });
    setOpenDialog(true);
  };

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      await reportService.generateReport(formData);
      setSuccess('Report generated successfully');
      setOpenDialog(false);
      fetchReports();
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to generate report');
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = async (reportId: number, title: string) => {
    try {
      const blob = await reportService.downloadReport(reportId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${title}.csv`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to download report');
    }
  };

  const handleLogout = async () => {
    await logout();
  };

  const getReportTypeColor = (type: string) => {
    switch (type) {
      case 'GEOFENCE_ANALYTICS': return 'primary';
      case 'USER_ACTIVITY': return 'secondary';
      case 'ALERT_SUMMARY': return 'warning';
      case 'SYSTEM_HEALTH': return 'success';
      case 'CUSTOM': return 'default';
      default: return 'default';
    }
  };

  if (!hasAccess) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <Alert severity="error">
          Access denied. Only SUPER_ADMIN can access this page.
        </Alert>
      </Box>
    );
  }

  return (
    <LocalizationProvider dateAdapter={AdapterDateFns}>
      <Box sx={{ flexGrow: 1 }}>
        <AppBar position="static">
          <Toolbar>
            <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
              Reports Management
            </Typography>
            <Typography variant="body1" sx={{ mr: 2 }}>
              Welcome, {user?.username} ({user?.role})
            </Typography>
            <Button color="inherit" onClick={handleLogout}>
              Logout
            </Button>
          </Toolbar>
        </AppBar>

        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
          {/* Success/Error Messages */}
          {success && (
            <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess('')}>
              {success}
            </Alert>
          )}
          {error && (
            <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
              {error}
            </Alert>
          )}

          {/* Status Cards */}
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Total Reports
                  </Typography>
                  <Typography variant="h4">
                    {totalCount}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Generated
                  </Typography>
                  <Typography variant="h4" color="success.main">
                    {reports.filter(report => report.is_generated).length}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    Pending
                  </Typography>
                  <Typography variant="h4" color="warning.main">
                    {reports.filter(report => !report.is_generated).length}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={12} sm={6} md={3}>
              <Card>
                <CardContent>
                  <Typography color="textSecondary" gutterBottom>
                    This Month
                  </Typography>
                  <Typography variant="h4">
                    {reports.filter(report => {
                      const reportDate = new Date(report.created_at);
                      const now = new Date();
                      return reportDate.getMonth() === now.getMonth() && 
                             reportDate.getFullYear() === now.getFullYear();
                    }).length}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Filters and Search */}
          <Paper sx={{ p: 2, mb: 2 }}>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} sm={4}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Search Reports..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  InputProps={{
                    startAdornment: <SearchIcon sx={{ mr: 1, color: 'action.active' }} />,
                  }}
                />
              </Grid>
              <Grid item xs={12} sm={3}>
                <FormControl fullWidth size="small">
                  <InputLabel>Type</InputLabel>
                  <Select
                    value={filterType}
                    onChange={(e) => setFilterType(e.target.value)}
                    label="Type"
                  >
                    <MenuItem value="">All Types</MenuItem>
                    <MenuItem value="GEOFENCE_ANALYTICS">Geofence Analytics</MenuItem>
                    <MenuItem value="USER_ACTIVITY">User Activity</MenuItem>
                    <MenuItem value="ALERT_SUMMARY">Alert Summary</MenuItem>
                    <MenuItem value="SYSTEM_HEALTH">System Health</MenuItem>
                    <MenuItem value="CUSTOM">Custom</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={3}>
                <FormControl fullWidth size="small">
                  <InputLabel>Status</InputLabel>
                  <Select
                    value={filterGenerated === null ? '' : filterGenerated}
                    onChange={(e) => setFilterGenerated(e.target.value === '' ? null : e.target.value === 'true')}
                    label="Status"
                  >
                    <MenuItem value="">All Status</MenuItem>
                    <MenuItem value="true">Generated</MenuItem>
                    <MenuItem value="false">Pending</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} sm={2}>
                <Button
                  variant="contained"
                  startIcon={<AddIcon />}
                  onClick={handleCreate}
                  fullWidth
                >
                  Generate
                </Button>
              </Grid>
            </Grid>
          </Paper>

          {/* Reports Table */}
          <Paper>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Type</TableCell>
                    <TableCell>Title</TableCell>
                    <TableCell>Date Range</TableCell>
                    <TableCell>Generated By</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Created</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={7} align="center">
                        <CircularProgress />
                      </TableCell>
                    </TableRow>
                  ) : reports.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} align="center">
                        No reports found
                      </TableCell>
                    </TableRow>
                  ) : (
                    reports.map((report) => (
                      <TableRow key={report.id}>
                        <TableCell>
                          <Chip
                            label={report.report_type.replace('_', ' ')}
                            color={getReportTypeColor(report.report_type) as any}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontWeight="medium">
                            {report.title}
                          </Typography>
                          {report.description && (
                            <Typography variant="caption" color="text.secondary">
                              {report.description}
                            </Typography>
                          )}
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {new Date(report.date_range_start).toLocaleDateString()} - {new Date(report.date_range_end).toLocaleDateString()}
                          </Typography>
                        </TableCell>
                        <TableCell>{report.generated_by_username}</TableCell>
                        <TableCell>
                          <Chip
                            label={report.is_generated ? 'Generated' : 'Pending'}
                            color={report.is_generated ? 'success' : 'warning'}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          {new Date(report.created_at).toLocaleString()}
                        </TableCell>
                        <TableCell>
                          {report.is_generated && (
                            <Tooltip title="Download CSV">
                              <IconButton
                                size="small"
                                onClick={() => handleDownload(report.id, report.title)}
                              >
                                <DownloadIcon />
                              </IconButton>
                            </Tooltip>
                          )}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* Pagination */}
          {totalPages > 1 && (
            <Box display="flex" justifyContent="center" mt={2}>
              <Pagination
                count={totalPages}
                page={page}
                onChange={(_, newPage) => setPage(newPage)}
                color="primary"
              />
            </Box>
          )}

          {/* Generate Report Dialog */}
          <Dialog open={openDialog} onClose={() => setOpenDialog(false)} maxWidth="md" fullWidth>
            <DialogTitle>Generate New Report</DialogTitle>
            <DialogContent>
              <Grid container spacing={2} sx={{ mt: 1 }}>
                <Grid item xs={12} sm={6}>
                  <FormControl fullWidth>
                    <InputLabel>Report Type</InputLabel>
                    <Select
                      value={formData.report_type}
                      onChange={(e) => setFormData(prev => ({ ...prev, report_type: e.target.value as any }))}
                      label="Report Type"
                    >
                      <MenuItem value="GEOFENCE_ANALYTICS">Geofence Analytics</MenuItem>
                      <MenuItem value="USER_ACTIVITY">User Activity</MenuItem>
                      <MenuItem value="ALERT_SUMMARY">Alert Summary</MenuItem>
                      <MenuItem value="SYSTEM_HEALTH">System Health</MenuItem>
                      <MenuItem value="CUSTOM">Custom</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <TextField
                    fullWidth
                    label="Title"
                    value={formData.title}
                    onChange={(e) => setFormData(prev => ({ ...prev, title: e.target.value }))}
                    required
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Description"
                    multiline
                    rows={2}
                    value={formData.description}
                    onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <DatePicker
                    label="Start Date"
                    value={new Date(formData.date_range_start)}
                    onChange={(date) => setFormData(prev => ({ 
                      ...prev, 
                      date_range_start: date?.toISOString() || new Date().toISOString() 
                    }))}
                    renderInput={(params) => <TextField {...params} fullWidth />}
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <DatePicker
                    label="End Date"
                    value={new Date(formData.date_range_end)}
                    onChange={(date) => setFormData(prev => ({ 
                      ...prev, 
                      date_range_end: date?.toISOString() || new Date().toISOString() 
                    }))}
                    renderInput={(params) => <TextField {...params} fullWidth />}
                  />
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setOpenDialog(false)} disabled={generating}>
                Cancel
              </Button>
              <Button
                onClick={handleGenerate}
                variant="contained"
                disabled={generating || !formData.title}
              >
                {generating ? <CircularProgress size={24} /> : 'Generate Report'}
              </Button>
            </DialogActions>
          </Dialog>
        </Container>
      </Box>
    </LocalizationProvider>
  );
};

export default Reports;
