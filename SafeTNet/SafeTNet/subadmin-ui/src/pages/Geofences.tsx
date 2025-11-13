import React, { useState, useEffect } from 'react';
import { MapContainer, TileLayer, Polygon, Popup, useMapEvents } from 'react-leaflet';
import { geofenceService } from '../services/api';
import { Geofence, PolygonData } from '../types';
import { Map, Plus, Edit, Trash2, Eye } from 'lucide-react';
import 'leaflet/dist/leaflet.css';

// Fix for default markers in react-leaflet
import L from 'leaflet';
delete (L.Icon.Default.prototype as any)._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: require('leaflet/dist/images/marker-icon-2x.png'),
  iconUrl: require('leaflet/dist/images/marker-icon.png'),
  shadowUrl: require('leaflet/dist/images/marker-shadow.png'),
});

interface GeofenceFormData {
  name: string;
  description: string;
  polygon_json: PolygonData | null;
}

const Geofences: React.FC = () => {
  const [geofences, setGeofences] = useState<Geofence[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editingGeofence, setEditingGeofence] = useState<Geofence | null>(null);
  const [formData, setFormData] = useState<GeofenceFormData>({
    name: '',
    description: '',
    polygon_json: null
  });
  const [drawingMode, setDrawingMode] = useState(false);
  const [currentPolygon, setCurrentPolygon] = useState<[number, number][]>([]);

  useEffect(() => {
    fetchGeofences();
  }, []);

  const fetchGeofences = async () => {
    try {
      const response = await geofenceService.getGeofences();
      setGeofences(response.results);
    } catch (err: any) {
      setError(err.message || 'Failed to load geofences');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.polygon_json) {
      setError('Please draw a polygon on the map');
      return;
    }

    try {
      if (editingGeofence) {
        await geofenceService.updateGeofence(editingGeofence.id, formData);
      } else {
        await geofenceService.createGeofence(formData);
      }
      
      setShowForm(false);
      setEditingGeofence(null);
      setFormData({ name: '', description: '', polygon_json: null });
      setCurrentPolygon([]);
      setDrawingMode(false);
      fetchGeofences();
    } catch (err: any) {
      setError(err.message || 'Failed to save geofence');
    }
  };

  const handleDelete = async (id: number) => {
    if (window.confirm('Are you sure you want to delete this geofence?')) {
      try {
        await geofenceService.deleteGeofence(id);
        fetchGeofences();
      } catch (err: any) {
        setError(err.message || 'Failed to delete geofence');
      }
    }
  };

  const startEditing = (geofence: Geofence) => {
    setEditingGeofence(geofence);
    setFormData({
      name: geofence.name,
      description: geofence.description || '',
      polygon_json: geofence.polygon_json
    });
    setShowForm(true);
  };

  const MapEvents = () => {
    useMapEvents({
      click: (e) => {
        if (drawingMode) {
          const { lat, lng } = e.latlng;
          setCurrentPolygon(prev => [...prev, [lat, lng]]);
        }
      }
    });
    return null;
  };

  const finishDrawing = () => {
    if (currentPolygon.length >= 3) {
      const polygonData: PolygonData = {
        type: 'Polygon',
        coordinates: [[...currentPolygon, currentPolygon[0]]] // Close the polygon
      };
      setFormData(prev => ({ ...prev, polygon_json: polygonData }));
      setDrawingMode(false);
    }
  };

  const resetDrawing = () => {
    setCurrentPolygon([]);
    setFormData(prev => ({ ...prev, polygon_json: null }));
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Geofences</h1>
          <p className="mt-1 text-sm text-gray-500">
            Manage your geofences and monitor specific areas
          </p>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
        >
          <Plus className="h-4 w-4 mr-2" />
          Add Geofence
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-md p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">Error</h3>
              <p className="mt-1 text-sm text-red-700">{error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Geofences List */}
      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        <ul className="divide-y divide-gray-200">
          {geofences.map((geofence) => (
            <li key={geofence.id}>
              <div className="px-4 py-4 flex items-center justify-between">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <Map className="h-8 w-8 text-primary-600" />
                  </div>
                  <div className="ml-4">
                    <div className="flex items-center">
                      <p className="text-sm font-medium text-gray-900">{geofence.name}</p>
                      <span className={`ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        geofence.active 
                          ? 'bg-green-100 text-green-800' 
                          : 'bg-red-100 text-red-800'
                      }`}>
                        {geofence.active ? 'Active' : 'Inactive'}
                      </span>
                    </div>
                    {geofence.description && (
                      <p className="text-sm text-gray-500">{geofence.description}</p>
                    )}
                    <p className="text-xs text-gray-400">
                      Created by {geofence.created_by_username} • {new Date(geofence.created_at).toLocaleDateString()}
                    </p>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => startEditing(geofence)}
                    className="text-primary-600 hover:text-primary-900"
                  >
                    <Edit className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => handleDelete(geofence.id)}
                    className="text-red-600 hover:text-red-900"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>

      {/* Form Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-11/12 max-w-4xl shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                {editingGeofence ? 'Edit Geofence' : 'Create New Geofence'}
              </h3>
              
              <form onSubmit={handleSubmit} className="space-y-4">
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div>
                    <label htmlFor="name" className="block text-sm font-medium text-gray-700">
                      Name
                    </label>
                    <input
                      type="text"
                      id="name"
                      required
                      value={formData.name}
                      onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                      className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                    />
                  </div>
                  <div>
                    <label htmlFor="description" className="block text-sm font-medium text-gray-700">
                      Description
                    </label>
                    <input
                      type="text"
                      id="description"
                      value={formData.description}
                      onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                      className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Draw Geofence
                  </label>
                  <div className="border rounded-lg overflow-hidden">
                    <MapContainer
                      center={[40.7128, -74.0060]}
                      zoom={13}
                      style={{ height: '400px', width: '100%' }}
                    >
                      <TileLayer
                        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                        attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                      />
                      <MapEvents />
                      
                      {/* Existing geofences */}
                      {geofences.map((geofence) => {
                        if (geofence.polygon_json && geofence.polygon_json.coordinates) {
                          return (
                            <Polygon
                              key={geofence.id}
                              positions={geofence.polygon_json.coordinates[0].map(coord => [coord[1], coord[0]])}
                              color={geofence.active ? 'blue' : 'red'}
                            >
                              <Popup>
                                <div>
                                  <h3 className="font-medium">{geofence.name}</h3>
                                  <p className="text-sm text-gray-600">{geofence.description}</p>
                                </div>
                              </Popup>
                            </Polygon>
                          );
                        }
                        return null;
                      })}
                      
                      {/* Current drawing polygon */}
                      {currentPolygon.length > 0 && (
                        <Polygon
                          positions={currentPolygon}
                          color="green"
                          fillOpacity={0.2}
                        />
                      )}
                    </MapContainer>
                  </div>
                  
                  <div className="mt-2 flex space-x-2">
                    {!drawingMode ? (
                      <button
                        type="button"
                        onClick={() => setDrawingMode(true)}
                        className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                      >
                        <Plus className="h-4 w-4 mr-1" />
                        Start Drawing
                      </button>
                    ) : (
                      <>
                        <button
                          type="button"
                          onClick={finishDrawing}
                          className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
                        >
                          Finish Drawing
                        </button>
                        <button
                          type="button"
                          onClick={resetDrawing}
                          className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                        >
                          Reset
                        </button>
                      </>
                    )}
                  </div>
                  
                  {formData.polygon_json && (
                    <p className="mt-2 text-sm text-green-600">
                      ✓ Geofence polygon is ready
                    </p>
                  )}
                </div>

                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => {
                      setShowForm(false);
                      setEditingGeofence(null);
                      setFormData({ name: '', description: '', polygon_json: null });
                      setCurrentPolygon([]);
                      setDrawingMode(false);
                    }}
                    className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                  >
                    {editingGeofence ? 'Update' : 'Create'} Geofence
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Geofences;
