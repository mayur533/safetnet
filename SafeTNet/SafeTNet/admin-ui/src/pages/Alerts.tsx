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
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Search as SearchIcon,
  Refresh as RefreshIcon,
  CheckCircle as ResolvedIcon,
  Error as CriticalIcon,
  Warning as HighIcon,
  Info as MediumIcon,
  Help as LowIcon,
  Alert as AlertType,
  Alert as MuiAlert,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';
import { alertService } from '../services/alertService';


const Alerts: React.FC = () => {
  const { user, logout } = useAuth();
  const [alerts, setAlerts] = useState<AlertType[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterResolved, setFilterResolved] = useState<boolean | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  // Check if user has access
  const hasAccess = user?.role === 'SUPER_ADMIN' || user?.role === 'SUB_ADMIN';

  useEffect(() => {
    if (hasAccess) {
      fetchAlerts();
      
      // Set up polling every 10 seconds
      const interval = setInterval(() => {
        fetchAlerts(true); // Silent refresh
      }, 10000);
      
      return () => clearInterval(interval);
    }
  }, [hasAccess, page, search, filterType, filterSeverity, filterResolved]);

  const fetchAlerts = async (silent = false) => {
    if (!silent) setLoading(true);
    setError('');
    try {
      const params: any = {
        page,
        page_size: 10,
      };
      
      if (search) params.search = search;
      if (filterType) params.alert_type = filterType;
      if (filterSeverity) params.severity = filterSeverity;
      if (filterResolved !== null) params.is_resolved = filterResolved;

      const response = await alertService.getAlerts(params);
      setAlerts(response.results);
      setTotalCount(response.count);
      setTotalPages(Math.ceil(response.count / 10));
      setLastUpdate(new Date());
    } catch (err: any) {
      if (!silent) {
        setError(err.response?.data?.message || 'Failed to fetch Alerts');
      }
    } finally {
      if (!silent) setLoading(false);
    }
  };

  const handleRefresh = () => {
    fetchAlerts();
  };

  const handleLogout = async () => {
    await logout();
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'error';
      case 'HIGH': return 'warning';
      case 'MEDIUM': return 'info';
      case 'LOW': return 'default';
      default: return 'default';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return <CriticalIcon />;
      case 'HIGH': return <HighIcon />;
      case 'MEDIUM': return <MediumIcon />;
      case 'LOW': return <LowIcon />;
      default: return <LowIcon />;
    }
  };

  const getAlertTypeColor = (type: string) => {
    switch (type) {
      case 'GEOFENCE_ENTER': return 'success';
      case 'GEOFENCE_EXIT': return 'info';
      case 'GEOFENCE_VIOLATION': return 'warning';
      case 'SYSTEM_ERROR': return 'error';
      case 'SECURITY_BREACH': return 'error';
      case 'MAINTENANCE': return 'default';
      default: return 'default';
    }
  };

  if (!hasAccess) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">
        <Alert severity="error">
          Access denied. Only SUPER_ADMIN and SUB_ADMIN can access this page.
        </Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1 }}>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            Alerts Management
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
                  Total Alerts
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
                  Unresolved
                </Typography>
                <Typography variant="h4" color="error">
                  {alerts.filter(alert => !alert.is_resolved).length}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Critical
                </Typography>
                <Typography variant="h4" color="error">
                  {alerts.filter(alert => alert.severity === 'CRITICAL' && !alert.is_resolved).length}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card>
              <CardContent>
                <Typography color="textSecondary" gutterBottom>
                  Last Update
                </Typography>
                <Typography variant="body2">
                  {lastUpdate.toLocaleTimeString()}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Filters and Search */}
        <Paper sx={{ p: 2, mb: 2 }}>
          <Grid container spacing={2} alignItems="center">
            <Grid item xs={12} sm={3}>
              <TextField
                fullWidth
                size="small"
                placeholder="Search Alerts..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                InputProps={{
                  startAdornment: <SearchIcon sx={{ mr: 1, color: 'action.active' }} />,
                }}
              />
            </Grid>
            <Grid item xs={12} sm={2}>
              <FormControl fullWidth size="small">
                <InputLabel>Type</InputLabel>
                <Select
                  value={filterType}
                  onChange={(e) => setFilterType(e.target.value)}
                  label="Type"
                >
                  <MenuItem value="">All Types</MenuItem>
                  <MenuItem value="GEOFENCE_ENTER">Geofence Enter</MenuItem>
                  <MenuItem value="GEOFENCE_EXIT">Geofence Exit</MenuItem>
                  <MenuItem value="GEOFENCE_VIOLATION">Geofence Violation</MenuItem>
                  <MenuItem value="SYSTEM_ERROR">System Error</MenuItem>
                  <MenuItem value="SECURITY_BREACH">Security Breach</MenuItem>
                  <MenuItem value="MAINTENANCE">Maintenance</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={2}>
              <FormControl fullWidth size="small">
                <InputLabel>Severity</InputLabel>
                <Select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  label="Severity"
                >
                  <MenuItem value="">All Severities</MenuItem>
                  <MenuItem value="CRITICAL">Critical</MenuItem>
                  <MenuItem value="HIGH">High</MenuItem>
                  <MenuItem value="MEDIUM">Medium</MenuItem>
                  <MenuItem value="LOW">Low</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={2}>
              <FormControl fullWidth size="small">
                <InputLabel>Status</InputLabel>
                <Select
                  value={filterResolved === null ? '' : filterResolved}
                  onChange={(e) => setFilterResolved(e.target.value === '' ? null : e.target.value === 'true')}
                  label="Status"
                >
                  <MenuItem value="">All Status</MenuItem>
                  <MenuItem value="false">Unresolved</MenuItem>
                  <MenuItem value="true">Resolved</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={3}>
              <Box display="flex" gap={1}>
                <Button
                  variant="outlined"
                  startIcon={<RefreshIcon />}
                  onClick={handleRefresh}
                  disabled={loading}
                >
                  Refresh
                </Button>
              </Box>
            </Grid>
          </Grid>
        </Paper>

        {/* Alerts Table */}
        <Paper>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Severity</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Title</TableCell>
                  <TableCell>Geofence</TableCell>
                  <TableCell>User</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Created</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={7} align="center">
                      <CircularProgress />
                    </TableCell>
                  </TableRow>
                ) : alerts.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} align="center">
                      No alerts found
                    </TableCell>
                  </TableRow>
                ) : (
                  alerts.map((alert) => (
                    <TableRow key={alert.id}>
                      <TableCell>
                        <Chip
                          icon={getSeverityIcon(alert.severity)}
                          label={alert.severity}
                          color={getSeverityColor(alert.severity) as any}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={alert.alert_type.replace('_', ' ')}
                          color={getAlertTypeColor(alert.alert_type) as any}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" fontWeight="medium">
                          {alert.title}
                        </Typography>
                        {alert.description && (
                          <Typography variant="caption" color="text.secondary">
                            {alert.description}
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>{alert.geofence_name || 'N/A'}</TableCell>
                      <TableCell>{alert.user_username || 'System'}</TableCell>
                      <TableCell>
                        <Chip
                          icon={alert.is_resolved ? <ResolvedIcon /> : undefined}
                          label={alert.is_resolved ? 'Resolved' : 'Unresolved'}
                          color={alert.is_resolved ? 'success' : 'default'}
                          size="small"
                        />
                      </TableCell>
                      <TableCell>
                        {new Date(alert.created_at).toLocaleString()}
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
      </Container>
    </Box>
  );
};

export default Alerts;
