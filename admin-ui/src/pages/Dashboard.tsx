import React, { useState, useEffect } from 'react';
import {
  Container,
  AppBar,
  Toolbar,
  Typography,
  Button,
  Box,
  Card,
  CardContent,
  Grid,
  Alert,
  CircularProgress,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { authService } from '../services/api';
import { dashboardService } from '../services/dashboardService';
import { DashboardKPIs } from '../types';

const Dashboard: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [testResult, setTestResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [kpis, setKpis] = useState<DashboardKPIs | null>(null);
  const [kpisLoading, setKpisLoading] = useState(false);

  const handleTestAuth = async () => {
    setLoading(true);
    setError('');
    try {
      const result = await authService.testAuth();
      setTestResult(result);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Test failed');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    await logout();
  };

  const fetchKPIs = async () => {
    setKpisLoading(true);
    try {
      const data = await dashboardService.getKPIs();
      setKpis(data);
    } catch (err: any) {
      console.error('Failed to fetch KPIs:', err);
    } finally {
      setKpisLoading(false);
    }
  };

  useEffect(() => {
    // Load KPIs asynchronously - don't block dashboard render
    fetchKPIs();
  }, []);

  return (
    <Box sx={{ flexGrow: 1 }}>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            Main Admin Panel
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
        <Grid container spacing={3}>
          {/* KPIs Section */}
          <Grid item xs={12}>
            <Typography variant="h5" gutterBottom>
              Key Performance Indicators
            </Typography>
            {kpisLoading ? (
              <Box display="flex" justifyContent="center" alignItems="center" minHeight={200}>
                <CircularProgress />
              </Box>
            ) : kpis ? (
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6} md={2}>
                  <Card>
                    <CardContent>
                      <Typography color="textSecondary" gutterBottom>
                        Active Geofences
                      </Typography>
                      <Typography variant="h4">
                        {kpis.active_geofences}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} sm={6} md={2}>
                  <Card>
                    <CardContent>
                      <Typography color="textSecondary" gutterBottom>
                        Alerts Today
                      </Typography>
                      <Typography variant="h4" color={kpis.alerts_today > 0 ? 'warning.main' : 'success.main'}>
                        {kpis.alerts_today}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} sm={6} md={2}>
                  <Card>
                    <CardContent>
                      <Typography color="textSecondary" gutterBottom>
                        Active Sub-Admins
                      </Typography>
                      <Typography variant="h4">
                        {kpis.active_sub_admins}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} sm={6} md={2}>
                  <Card>
                    <CardContent>
                      <Typography color="textSecondary" gutterBottom>
                        Total Users
                      </Typography>
                      <Typography variant="h4">
                        {kpis.total_users}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} sm={6} md={2}>
                  <Card>
                    <CardContent>
                      <Typography color="textSecondary" gutterBottom>
                        Critical Alerts
                      </Typography>
                      <Typography variant="h4" color={kpis.critical_alerts > 0 ? 'error.main' : 'success.main'}>
                        {kpis.critical_alerts}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={12} sm={6} md={2}>
                  <Card>
                    <CardContent>
                      <Typography color="textSecondary" gutterBottom>
                        System Health
                      </Typography>
                      <Typography variant="h6" color={kpis.system_health === 'Good' ? 'success.main' : 'warning.main'}>
                        {kpis.system_health}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>
            ) : null}
          </Grid>

          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h5" gutterBottom>
                  Dashboard
                </Typography>
                <Typography variant="body1" color="text.secondary">
                  Welcome to the Main Admin Panel. You are successfully authenticated!
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Authentication Test
                </Typography>
                <Button
                  variant="contained"
                  onClick={handleTestAuth}
                  disabled={loading}
                  sx={{ mb: 2 }}
                >
                  {loading ? <CircularProgress size={24} /> : 'Test Protected Route'}
                </Button>

                {error && (
                  <Alert severity="error" sx={{ mb: 2 }}>
                    {error}
                  </Alert>
                )}

                {testResult && (
                  <Alert severity="success">
                    <Typography variant="body2">
                      <strong>Message:</strong> {testResult.message}
                    </Typography>
                    <Typography variant="body2">
                      <strong>User:</strong> {testResult.user}
                    </Typography>
                    <Typography variant="body2">
                      <strong>Role:</strong> {testResult.role}
                    </Typography>
                  </Alert>
                )}
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  User Information
                </Typography>
                <Typography variant="body2">
                  <strong>ID:</strong> {user?.id}
                </Typography>
                <Typography variant="body2">
                  <strong>Username:</strong> {user?.username}
                </Typography>
                <Typography variant="body2">
                  <strong>Email:</strong> {user?.email}
                </Typography>
                <Typography variant="body2">
                  <strong>Role:</strong> {user?.role}
                </Typography>
                <Typography variant="body2">
                  <strong>Active:</strong> {user?.is_active ? 'Yes' : 'No'}
                </Typography>
                <Typography variant="body2">
                  <strong>Joined:</strong> {user?.date_joined ? new Date(user.date_joined).toLocaleDateString() : 'N/A'}
                </Typography>
              </CardContent>
            </Card>
          </Grid>

          {(user?.role === 'SUPER_ADMIN' || user?.role === 'SUB_ADMIN') && (
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Management Actions
                  </Typography>
                  <Box display="flex" gap={2} flexWrap="wrap">
                    {user?.role === 'SUPER_ADMIN' && (
                      <Button
                        variant="contained"
                        onClick={() => navigate('/subadmins')}
                      >
                        Manage Sub-Admins
                      </Button>
                    )}
                    <Button
                      variant="contained"
                      onClick={() => navigate('/geofences')}
                    >
                      Manage Geofences
                    </Button>
                    <Button
                      variant="contained"
                      onClick={() => navigate('/users')}
                    >
                      View Users
                    </Button>
                    <Button
                      variant="contained"
                      onClick={() => navigate('/alerts')}
                    >
                      View Alerts
                    </Button>
                    {user?.role === 'SUPER_ADMIN' && (
                      <Button
                        variant="contained"
                        onClick={() => navigate('/reports')}
                      >
                        Generate Reports
                      </Button>
                    )}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </Container>
    </Box>
  );
};

export default Dashboard;
