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
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  Pagination,
  Alert,
  CircularProgress,
  Tooltip,
  Grid,
  Paper,
} from '@mui/material';
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Search as SearchIcon,
  LocationOn as LocationIcon,
} from '@mui/icons-material';
import { MapContainer, TileLayer, Polygon, Popup, useMap } from 'react-leaflet';
import L from 'leaflet';
import { useAuth } from '../contexts/AuthContext';
import { geofenceService } from '../services/geofenceService';
import { Geofence, GeofenceCreateRequest, GeofenceUpdateRequest } from '../types';
import GeofenceForm from '../components/GeofenceForm';
import 'leaflet/dist/leaflet.css';

// Fix for default markers in react-leaflet
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: require('leaflet/dist/images/marker-icon-2x.png'),
  iconUrl: require('leaflet/dist/images/marker-icon.png'),
  shadowUrl: require('leaflet/dist/images/marker-shadow.png'),
});

const Geofences: React.FC = () => {
  const { user, logout } = useAuth();
  const [geofences, setGeofences] = useState<Geofence[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [search, setSearch] = useState('');
  const [filterActive, setFilterActive] = useState<boolean | null>(null);
  
  // Dialog states
  const [openDialog, setOpenDialog] = useState(false);
  const [editingGeofence, setEditingGeofence] = useState<Geofence | null>(null);
  const [deleteDialog, setDeleteDialog] = useState(false);
  const [deletingId, setDeletingId] = useState<number | null>(null);

  // Check if user has access
  const hasAccess = user?.role === 'SUPER_ADMIN' || user?.role === 'SUB_ADMIN';

  useEffect(() => {
    if (hasAccess) {
      fetchGeofences();
    }
  }, [hasAccess, page, search, filterActive]);

  const fetchGeofences = async () => {
    setLoading(true);
    setError('');
    try {
      const params: any = {
        page,
        page_size: 10,
      };
      
      if (search) params.search = search;
      if (filterActive !== null) params.active = filterActive;

      const response = await geofenceService.getGeofences(params);
      setGeofences(response.results);
      setTotalCount(response.count);
      setTotalPages(Math.ceil(response.count / 10));
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to fetch Geofences');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = () => {
    setEditingGeofence(null);
    setOpenDialog(true);
  };

  const handleEdit = (geofence: Geofence) => {
    setEditingGeofence(geofence);
    setOpenDialog(true);
  };

  const handleDelete = (id: number) => {
    setDeletingId(id);
    setDeleteDialog(true);
  };

  const confirmDelete = async () => {
    if (!deletingId) return;
    
    try {
      await geofenceService.deleteGeofence(deletingId);
      setSuccess('Geofence deleted successfully');
      fetchGeofences();
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to delete Geofence');
    } finally {
      setDeleteDialog(false);
      setDeletingId(null);
    }
  };

  const handleFormSubmit = async (data: GeofenceCreateRequest | GeofenceUpdateRequest) => {
    try {
      if (editingGeofence) {
        await geofenceService.updateGeofence(editingGeofence.id, data as GeofenceUpdateRequest);
        setSuccess('Geofence updated successfully');
      } else {
        await geofenceService.createGeofence(data as GeofenceCreateRequest);
        setSuccess('Geofence created successfully');
      }
      setOpenDialog(false);
      fetchGeofences();
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to save Geofence');
    }
  };

  const handleLogout = async () => {
    await logout();
  };

  const getPolygonCoordinates = (geofence: Geofence) => {
    try {
      if (geofence.polygon_json?.coordinates) {
        return geofence.polygon_json.coordinates[0].map((coord: [number, number]) => [coord[1], coord[0]]);
      }
      return [];
    } catch {
      return [];
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
            Geofences Management
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

        {/* Filters and Search */}
        <Paper sx={{ p: 2, mb: 2 }}>
          <Box display="flex" gap={2} alignItems="center" flexWrap="wrap">
            <TextField
              size="small"
              placeholder="Search Geofences..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              InputProps={{
                startAdornment: <SearchIcon sx={{ mr: 1, color: 'action.active' }} />,
              }}
              sx={{ minWidth: 200 }}
            />
            <FormControl size="small" sx={{ minWidth: 120 }}>
              <InputLabel>Status</InputLabel>
              <Select
                value={filterActive === null ? '' : filterActive}
                onChange={(e) => setFilterActive(e.target.value === '' ? null : e.target.value === 'true')}
                label="Status"
              >
                <MenuItem value="">All</MenuItem>
                <MenuItem value="true">Active</MenuItem>
                <MenuItem value="false">Inactive</MenuItem>
              </Select>
            </FormControl>
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={handleCreate}
              sx={{ ml: 'auto' }}
            >
              Add Geofence
            </Button>
          </Box>
        </Paper>

        <Grid container spacing={3}>
          {/* Geofences List */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Geofences List
                </Typography>
                {loading ? (
                  <Box display="flex" justifyContent="center" p={2}>
                    <CircularProgress />
                  </Box>
                ) : geofences.length === 0 ? (
                  <Typography variant="body2" color="text.secondary" align="center" p={2}>
                    No Geofences found
                  </Typography>
                ) : (
                  <Box>
                    {geofences.map((geofence) => (
                      <Card key={geofence.id} sx={{ mb: 1, p: 1 }}>
                        <Box display="flex" justifyContent="space-between" alignItems="center">
                          <Box>
                            <Typography variant="subtitle2">{geofence.name}</Typography>
                            <Typography variant="body2" color="text.secondary">
                              {geofence.organization_name}
                            </Typography>
                            <Box display="flex" gap={1} mt={0.5}>
                              <Chip
                                label={geofence.active ? 'Active' : 'Inactive'}
                                color={geofence.active ? 'success' : 'default'}
                                size="small"
                              />
                              <Chip
                                label={new Date(geofence.created_at).toLocaleDateString()}
                                variant="outlined"
                                size="small"
                              />
                            </Box>
                          </Box>
                          <Box>
                            <Tooltip title="Edit">
                              <IconButton
                                size="small"
                                onClick={() => handleEdit(geofence)}
                              >
                                <EditIcon />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title="Delete">
                              <IconButton
                                size="small"
                                color="error"
                                onClick={() => handleDelete(geofence.id)}
                              >
                                <DeleteIcon />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </Box>
                      </Card>
                    ))}
                    
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
                  </Box>
                )}
              </CardContent>
            </Card>
          </Grid>

          {/* Map View */}
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Map View
                </Typography>
                <Box height={400} width="100%">
                  <MapContainer
                    center={[40.7128, -74.0060]} // Default to NYC
                    zoom={10}
                    style={{ height: '100%', width: '100%' }}
                  >
                    <TileLayer
                      url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                      attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                    />
                    {geofences.map((geofence) => {
                      const coordinates = getPolygonCoordinates(geofence);
                      if (coordinates.length === 0) return null;
                      
                      return (
                        <Polygon
                          key={geofence.id}
                          positions={coordinates}
                          color={geofence.active ? '#3388ff' : '#ff0000'}
                          fillColor={geofence.active ? '#3388ff' : '#ff0000'}
                          fillOpacity={0.2}
                        >
                          <Popup>
                            <div>
                              <strong>{geofence.name}</strong>
                              <br />
                              {geofence.description}
                              <br />
                              <small>
                                {geofence.organization_name} - {geofence.active ? 'Active' : 'Inactive'}
                              </small>
                            </div>
                          </Popup>
                        </Polygon>
                      );
                    })}
                  </MapContainer>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Geofence Form Dialog */}
        <GeofenceForm
          open={openDialog}
          onClose={() => setOpenDialog(false)}
          onSubmit={handleFormSubmit}
          geofence={editingGeofence}
        />

        {/* Delete Confirmation Dialog */}
        <Dialog open={deleteDialog} onClose={() => setDeleteDialog(false)}>
          <DialogTitle>Confirm Delete</DialogTitle>
          <DialogContent>
            Are you sure you want to delete this Geofence? This action cannot be undone.
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setDeleteDialog(false)}>Cancel</Button>
            <Button onClick={confirmDelete} color="error" variant="contained">
              Delete
            </Button>
          </DialogActions>
        </Dialog>
      </Container>
    </Box>
  );
};

export default Geofences;
