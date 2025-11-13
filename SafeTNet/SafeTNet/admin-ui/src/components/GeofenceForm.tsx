import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormControlLabel,
  Switch,
  Button,
  Grid,
  Alert,
  Box,
  Typography,
} from '@mui/material';
import { MapContainer, TileLayer, Polygon, useMapEvents } from 'react-leaflet';
import L from 'leaflet';
import { Geofence, GeofenceCreateRequest, GeofenceUpdateRequest } from '../types';

// Fix for default markers in react-leaflet
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: require('leaflet/dist/images/marker-icon-2x.png'),
  iconUrl: require('leaflet/dist/images/marker-icon.png'),
  shadowUrl: require('leaflet/dist/images/marker-shadow.png'),
});

interface GeofenceFormProps {
  open: boolean;
  onClose: () => void;
  onSubmit: (data: GeofenceCreateRequest | GeofenceUpdateRequest) => void;
  geofence?: Geofence | null;
}

// Component to handle map clicks for drawing polygons
const MapClickHandler: React.FC<{
  onPolygonComplete: (coordinates: [number, number][]) => void;
  initialCoordinates?: [number, number][];
}> = ({ onPolygonComplete, initialCoordinates }) => {
  const [points, setPoints] = useState<[number, number][]>(initialCoordinates || []);
  const [isDrawing, setIsDrawing] = useState(!initialCoordinates);

  useMapEvents({
    click: (e) => {
      if (isDrawing) {
        const newPoint: [number, number] = [e.latlng.lat, e.latlng.lng];
        const newPoints = [...points, newPoint];
        setPoints(newPoints);
        
        // Auto-complete polygon after 3 points
        if (newPoints.length >= 3) {
          onPolygonComplete(newPoints);
          setIsDrawing(false);
        }
      }
    },
  });

  return (
    <>
      {points.length > 0 && (
        <Polygon
          positions={points}
          color="#3388ff"
          fillColor="#3388ff"
          fillOpacity={0.2}
        />
      )}
    </>
  );
};

const GeofenceForm: React.FC<GeofenceFormProps> = ({
  open,
  onClose,
  onSubmit,
  geofence,
}) => {
  const [formData, setFormData] = useState<GeofenceCreateRequest>({
    name: '',
    description: '',
    polygon_json: null,
    organization: 1, // Default organization ID
    active: true,
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [polygonCoordinates, setPolygonCoordinates] = useState<[number, number][]>([]);

  const isEditing = !!geofence;

  useEffect(() => {
    if (geofence) {
      setFormData({
        name: geofence.name,
        description: geofence.description || '',
        polygon_json: geofence.polygon_json,
        organization: geofence.organization,
        active: geofence.active,
      });
      
      // Extract coordinates for display
      try {
        if (geofence.polygon_json?.coordinates?.[0]) {
          const coords = geofence.polygon_json.coordinates[0].map((coord: [number, number]) => [coord[1], coord[0]]);
          setPolygonCoordinates(coords);
        }
      } catch (error) {
        console.error('Error parsing polygon coordinates:', error);
      }
    } else {
      setFormData({
        name: '',
        description: '',
        polygon_json: null,
        organization: 1,
        active: true,
      });
      setPolygonCoordinates([]);
    }
    setErrors({});
  }, [geofence, open]);

  const handleChange = (field: keyof GeofenceCreateRequest) => (
    event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement> | any
  ) => {
    const value = event.target.type === 'checkbox' ? event.target.checked : event.target.value;
    setFormData(prev => ({
      ...prev,
      [field]: value,
    }));
    
    // Clear error when user starts typing
    if (errors[field]) {
      setErrors(prev => ({
        ...prev,
        [field]: '',
      }));
    }
  };

  const handlePolygonComplete = (coordinates: [number, number][]) => {
    setPolygonCoordinates(coordinates);
    
    // Convert to GeoJSON format
    const geoJson = {
      type: 'Polygon',
      coordinates: [coordinates.map(coord => [coord[1], coord[0]])] // Convert lat,lng to lng,lat
    };
    
    setFormData(prev => ({
      ...prev,
      polygon_json: geoJson,
    }));
  };

  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Name is required';
    }
    
    if (!isEditing && !formData.polygon_json) {
      newErrors.polygon = 'Please draw a polygon on the map';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setLoading(true);
    try {
      if (isEditing) {
        const updateData: GeofenceUpdateRequest = {
          name: formData.name,
          description: formData.description,
          active: formData.active,
        };
        onSubmit(updateData);
      } else {
        onSubmit(formData);
      }
    } catch (error) {
      console.error('Form submission error:', error);
    } finally {
      setLoading(false);
    }
  };

  const resetDrawing = () => {
    setPolygonCoordinates([]);
    setFormData(prev => ({
      ...prev,
      polygon_json: null,
    }));
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="lg" fullWidth>
      <DialogTitle>
        {isEditing ? 'Edit Geofence' : 'Create New Geofence'}
      </DialogTitle>
      <form onSubmit={handleSubmit}>
        <DialogContent>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <TextField
                fullWidth
                label="Name"
                value={formData.name}
                onChange={handleChange('name')}
                error={!!errors.name}
                helperText={errors.name}
                required
              />
            </Grid>
            
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth>
                <InputLabel>Organization</InputLabel>
                <Select
                  value={formData.organization}
                  onChange={handleChange('organization')}
                  label="Organization"
                  disabled={isEditing} // Don't allow changing organization when editing
                >
                  <MenuItem value={1}>Default Organization</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Description"
                multiline
                rows={2}
                value={formData.description}
                onChange={handleChange('description')}
              />
            </Grid>
            
            <Grid item xs={12}>
              <FormControlLabel
                control={
                  <Switch
                    checked={formData.active}
                    onChange={handleChange('active')}
                  />
                }
                label="Active"
              />
            </Grid>
            
            <Grid item xs={12}>
              <Typography variant="h6" gutterBottom>
                {isEditing ? 'Geofence Map' : 'Draw Geofence'}
              </Typography>
              {!isEditing && (
                <Alert severity="info" sx={{ mb: 2 }}>
                  Click on the map to draw a polygon. Click at least 3 points to create a geofence.
                </Alert>
              )}
              <Box height={400} width="100%">
                <MapContainer
                  center={[40.7128, -74.0060]}
                  zoom={10}
                  style={{ height: '100%', width: '100%' }}
                >
                  <TileLayer
                    url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                    attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                  />
                  {!isEditing && (
                    <MapClickHandler
                      onPolygonComplete={handlePolygonComplete}
                      initialCoordinates={polygonCoordinates}
                    />
                  )}
                  {isEditing && polygonCoordinates.length > 0 && (
                    <Polygon
                      positions={polygonCoordinates}
                      color="#3388ff"
                      fillColor="#3388ff"
                      fillOpacity={0.2}
                    />
                  )}
                </MapContainer>
              </Box>
              {!isEditing && (
                <Box mt={1}>
                  <Button
                    variant="outlined"
                    onClick={resetDrawing}
                    disabled={polygonCoordinates.length === 0}
                  >
                    Reset Drawing
                  </Button>
                </Box>
              )}
              {errors.polygon && (
                <Alert severity="error" sx={{ mt: 1 }}>
                  {errors.polygon}
                </Alert>
              )}
            </Grid>
          </Grid>
        </DialogContent>
        
        <DialogActions>
          <Button onClick={onClose} disabled={loading}>
            Cancel
          </Button>
          <Button
            type="submit"
            variant="contained"
            disabled={loading}
          >
            {loading ? 'Saving...' : (isEditing ? 'Update' : 'Create')}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
};

export default GeofenceForm;
