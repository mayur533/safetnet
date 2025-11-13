import React, { useState, useEffect } from 'react';
import { incidentService, geofenceService, officerService } from '../services/api';
import { Incident, Geofence, SecurityOfficer } from '../types';
import { AlertTriangle, Plus, Edit, CheckCircle, Clock, MapPin, User, Filter, X, Calendar } from 'lucide-react';

interface IncidentFormData {
  geofence: number | '';
  officer: number | '';
  incident_type: string;
  severity: string;
  title: string;
  details: string;
  location: any;
}

const Incidents: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [filteredIncidents, setFilteredIncidents] = useState<Incident[]>([]);
  const [geofences, setGeofences] = useState<Geofence[]>([]);
  const [officers, setOfficers] = useState<SecurityOfficer[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [showDetailDrawer, setShowDetailDrawer] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [editingIncident, setEditingIncident] = useState<Incident | null>(null);
  const [filters, setFilters] = useState({
    geofence: '',
    dateFrom: '',
    dateTo: '',
    severity: '',
    is_resolved: ''
  });
  const [formData, setFormData] = useState<IncidentFormData>({
    geofence: '',
    officer: '',
    incident_type: 'SUSPICIOUS_ACTIVITY',
    severity: 'MEDIUM',
    title: '',
    details: '',
    location: {}
  });

  const incidentTypes = [
    { value: 'SECURITY_BREACH', label: 'Security Breach' },
    { value: 'UNAUTHORIZED_ACCESS', label: 'Unauthorized Access' },
    { value: 'SUSPICIOUS_ACTIVITY', label: 'Suspicious Activity' },
    { value: 'EMERGENCY', label: 'Emergency' },
    { value: 'MAINTENANCE', label: 'Maintenance' },
    { value: 'OTHER', label: 'Other' }
  ];

  const severityLevels = [
    { value: 'LOW', label: 'Low', color: 'bg-green-100 text-green-800' },
    { value: 'MEDIUM', label: 'Medium', color: 'bg-yellow-100 text-yellow-800' },
    { value: 'HIGH', label: 'High', color: 'bg-orange-100 text-orange-800' },
    { value: 'CRITICAL', label: 'Critical', color: 'bg-red-100 text-red-800' }
  ];

  useEffect(() => {
    fetchData();
  }, []);

  useEffect(() => {
    applyFilters();
  }, [incidents, filters]);

  const fetchData = async () => {
    try {
      const [incidentsResponse, geofencesResponse, officersResponse] = await Promise.all([
        incidentService.getIncidents(),
        geofenceService.getGeofences(),
        officerService.getOfficers()
      ]);
      setIncidents(incidentsResponse.results);
      setGeofences(geofencesResponse.results);
      setOfficers(officersResponse.results);
    } catch (err: any) {
      setError(err.message || 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = [...incidents];

    if (filters.geofence) {
      filtered = filtered.filter(incident => incident.geofence === Number(filters.geofence));
    }

    if (filters.severity) {
      filtered = filtered.filter(incident => incident.severity === filters.severity);
    }

    if (filters.is_resolved !== '') {
      filtered = filtered.filter(incident => incident.is_resolved === (filters.is_resolved === 'true'));
    }

    if (filters.dateFrom) {
      filtered = filtered.filter(incident => 
        new Date(incident.created_at) >= new Date(filters.dateFrom)
      );
    }

    if (filters.dateTo) {
      filtered = filtered.filter(incident => 
        new Date(incident.created_at) <= new Date(filters.dateTo)
      );
    }

    setFilteredIncidents(filtered);
  };

  const clearFilters = () => {
    setFilters({
      geofence: '',
      dateFrom: '',
      dateTo: '',
      severity: '',
      is_resolved: ''
    });
  };

  const openDetailDrawer = (incident: Incident) => {
    setSelectedIncident(incident);
    setShowDetailDrawer(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    const submitData = {
      ...formData,
      geofence: formData.geofence || undefined,
      officer: formData.officer || undefined
    };

    try {
      if (editingIncident) {
        await incidentService.updateIncident(editingIncident.id, submitData);
      } else {
        await incidentService.createIncident(submitData);
      }
      
      setShowForm(false);
      setEditingIncident(null);
      setFormData({
        geofence: '',
        officer: '',
        incident_type: 'SUSPICIOUS_ACTIVITY',
        severity: 'MEDIUM',
        title: '',
        details: '',
        location: {}
      });
      fetchData();
    } catch (err: any) {
      setError(err.message || 'Failed to save incident');
    }
  };

  const handleResolve = async (id: number) => {
    if (window.confirm('Are you sure you want to mark this incident as resolved?')) {
      try {
        await incidentService.resolveIncident(id);
        fetchData();
      } catch (err: any) {
        setError(err.message || 'Failed to resolve incident');
      }
    }
  };

  const startEditing = (incident: Incident) => {
    setEditingIncident(incident);
    setFormData({
      geofence: incident.geofence,
      officer: incident.officer || '',
      incident_type: incident.incident_type,
      severity: incident.severity,
      title: incident.title,
      details: incident.details,
      location: incident.location
    });
    setShowForm(true);
  };

  const getSeverityColor = (severity: string) => {
    const level = severityLevels.find(s => s.value === severity);
    return level ? level.color : 'bg-gray-100 text-gray-800';
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
          <h1 className="text-2xl font-bold text-gray-900">Incidents</h1>
          <p className="mt-1 text-sm text-gray-500">
            Track and manage security incidents
          </p>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
        >
          <Plus className="h-4 w-4 mr-2" />
          Report Incident
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

      {/* Filters */}
      <div className="bg-white shadow rounded-lg p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-medium text-gray-900">Filters</h3>
          <button
            onClick={clearFilters}
            className="text-sm text-primary-600 hover:text-primary-900"
          >
            Clear All
          </button>
        </div>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Geofence</label>
            <select
              value={filters.geofence}
              onChange={(e) => setFilters(prev => ({ ...prev, geofence: e.target.value }))}
              className="block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
            >
              <option value="">All Geofences</option>
              {geofences.map((geofence) => (
                <option key={geofence.id} value={geofence.id}>
                  {geofence.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
            <select
              value={filters.severity}
              onChange={(e) => setFilters(prev => ({ ...prev, severity: e.target.value }))}
              className="block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
            >
              <option value="">All Severities</option>
              {severityLevels.map((level) => (
                <option key={level.value} value={level.value}>
                  {level.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
            <select
              value={filters.is_resolved}
              onChange={(e) => setFilters(prev => ({ ...prev, is_resolved: e.target.value }))}
              className="block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
            >
              <option value="">All Status</option>
              <option value="false">Open</option>
              <option value="true">Resolved</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Date From</label>
            <input
              type="date"
              value={filters.dateFrom}
              onChange={(e) => setFilters(prev => ({ ...prev, dateFrom: e.target.value }))}
              className="block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Date To</label>
            <input
              type="date"
              value={filters.dateTo}
              onChange={(e) => setFilters(prev => ({ ...prev, dateTo: e.target.value }))}
              className="block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
            />
          </div>
        </div>
      </div>

      {/* Incidents List */}
      <div className="bg-white shadow overflow-hidden sm:rounded-md">
        <ul className="divide-y divide-gray-200">
          {filteredIncidents.map((incident) => (
            <li key={incident.id}>
              <div className="px-4 py-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center">
                    <div className="flex-shrink-0">
                      <AlertTriangle className={`h-8 w-8 ${
                        incident.severity === 'CRITICAL' ? 'text-red-600' :
                        incident.severity === 'HIGH' ? 'text-orange-600' :
                        incident.severity === 'MEDIUM' ? 'text-yellow-600' :
                        'text-green-600'
                      }`} />
                    </div>
                    <div className="ml-4 flex-1">
                      <div className="flex items-center">
                        <h3 
                          className="text-lg font-medium text-gray-900 cursor-pointer hover:text-primary-600"
                          onClick={() => openDetailDrawer(incident)}
                        >
                          {incident.title}
                        </h3>
                        <span className={`ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(incident.severity)}`}>
                          {severityLevels.find(s => s.value === incident.severity)?.label}
                        </span>
                        {incident.is_resolved ? (
                          <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Resolved
                          </span>
                        ) : (
                          <span className="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800">
                            <Clock className="h-3 w-3 mr-1" />
                            Open
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-gray-500 mt-1">{incident.details}</p>
                      <div className="mt-2 flex items-center space-x-4 text-xs text-gray-400">
                        <div className="flex items-center">
                          <MapPin className="h-3 w-3 mr-1" />
                          {incident.geofence_name}
                        </div>
                        {incident.officer_name && (
                          <div className="flex items-center">
                            <User className="h-3 w-3 mr-1" />
                            {incident.officer_name}
                          </div>
                        )}
                        <div>
                          {new Date(incident.created_at).toLocaleString()}
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    {!incident.is_resolved && (
                      <button
                        onClick={() => handleResolve(incident.id)}
                        className="text-green-600 hover:text-green-900"
                        title="Mark as resolved"
                      >
                        <CheckCircle className="h-4 w-4" />
                      </button>
                    )}
                    <button
                      onClick={() => startEditing(incident)}
                      className="text-primary-600 hover:text-primary-900"
                    >
                      <Edit className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>

      {/* Form Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-11/12 max-w-md shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                {editingIncident ? 'Edit Incident' : 'Report New Incident'}
              </h3>
              
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label htmlFor="title" className="block text-sm font-medium text-gray-700">
                    Title *
                  </label>
                  <input
                    type="text"
                    id="title"
                    required
                    value={formData.title}
                    onChange={(e) => setFormData(prev => ({ ...prev, title: e.target.value }))}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                  />
                </div>

                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div>
                    <label htmlFor="incident_type" className="block text-sm font-medium text-gray-700">
                      Type *
                    </label>
                    <select
                      id="incident_type"
                      required
                      value={formData.incident_type}
                      onChange={(e) => setFormData(prev => ({ ...prev, incident_type: e.target.value }))}
                      className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                    >
                      {incidentTypes.map((type) => (
                        <option key={type.value} value={type.value}>
                          {type.label}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label htmlFor="severity" className="block text-sm font-medium text-gray-700">
                      Severity *
                    </label>
                    <select
                      id="severity"
                      required
                      value={formData.severity}
                      onChange={(e) => setFormData(prev => ({ ...prev, severity: e.target.value }))}
                      className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                    >
                      {severityLevels.map((level) => (
                        <option key={level.value} value={level.value}>
                          {level.label}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div>
                  <label htmlFor="geofence" className="block text-sm font-medium text-gray-700">
                    Geofence *
                  </label>
                  <select
                    id="geofence"
                    required
                    value={formData.geofence}
                    onChange={(e) => setFormData(prev => ({ ...prev, geofence: e.target.value ? Number(e.target.value) : '' }))}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                  >
                    <option value="">Select geofence</option>
                    {geofences.map((geofence) => (
                      <option key={geofence.id} value={geofence.id}>
                        {geofence.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="officer" className="block text-sm font-medium text-gray-700">
                    Reporting Officer
                  </label>
                  <select
                    id="officer"
                    value={formData.officer}
                    onChange={(e) => setFormData(prev => ({ ...prev, officer: e.target.value ? Number(e.target.value) : '' }))}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                  >
                    <option value="">Select officer</option>
                    {officers.map((officer) => (
                      <option key={officer.id} value={officer.id}>
                        {officer.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="details" className="block text-sm font-medium text-gray-700">
                    Details *
                  </label>
                  <textarea
                    id="details"
                    required
                    rows={3}
                    value={formData.details}
                    onChange={(e) => setFormData(prev => ({ ...prev, details: e.target.value }))}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                    placeholder="Describe the incident in detail..."
                  />
                </div>

                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => {
                      setShowForm(false);
                      setEditingIncident(null);
                      setFormData({
                        geofence: '',
                        officer: '',
                        incident_type: 'SUSPICIOUS_ACTIVITY',
                        severity: 'MEDIUM',
                        title: '',
                        details: '',
                        location: {}
                      });
                    }}
                    className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                  >
                    {editingIncident ? 'Update' : 'Report'} Incident
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Detail Drawer */}
      {showDetailDrawer && selectedIncident && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-11/12 max-w-2xl shadow-lg rounded-md bg-white">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-medium text-gray-900">Incident Details</h3>
              <button
                onClick={() => setShowDetailDrawer(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <X className="h-6 w-6" />
              </button>
            </div>
            
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Title</label>
                  <p className="mt-1 text-sm text-gray-900">{selectedIncident.title}</p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Type</label>
                  <p className="mt-1 text-sm text-gray-900">
                    {incidentTypes.find(t => t.value === selectedIncident.incident_type)?.label}
                  </p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Severity</label>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getSeverityColor(selectedIncident.severity)}`}>
                    {severityLevels.find(s => s.value === selectedIncident.severity)?.label}
                  </span>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Status</label>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    selectedIncident.is_resolved
                      ? 'bg-green-100 text-green-800'
                      : 'bg-yellow-100 text-yellow-800'
                  }`}>
                    {selectedIncident.is_resolved ? 'Resolved' : 'Open'}
                  </span>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Geofence</label>
                  <p className="mt-1 text-sm text-gray-900">{selectedIncident.geofence_name}</p>
                </div>
                {selectedIncident.officer_name && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Reporting Officer</label>
                    <p className="mt-1 text-sm text-gray-900">{selectedIncident.officer_name}</p>
                  </div>
                )}
                <div>
                  <label className="block text-sm font-medium text-gray-700">Created</label>
                  <p className="mt-1 text-sm text-gray-900">
                    {new Date(selectedIncident.created_at).toLocaleString()}
                  </p>
                </div>
                {selectedIncident.resolved_at && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700">Resolved</label>
                    <p className="mt-1 text-sm text-gray-900">
                      {new Date(selectedIncident.resolved_at).toLocaleString()}
                    </p>
                  </div>
                )}
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Details</label>
                <p className="mt-1 text-sm text-gray-900 whitespace-pre-wrap">{selectedIncident.details}</p>
              </div>

              {selectedIncident.location && Object.keys(selectedIncident.location).length > 0 && (
                <div>
                  <label className="block text-sm font-medium text-gray-700">Location</label>
                  <p className="mt-1 text-sm text-gray-900">
                    {JSON.stringify(selectedIncident.location, null, 2)}
                  </p>
                </div>
              )}

              <div className="flex justify-end space-x-3 pt-4 border-t">
                <button
                  onClick={() => setShowDetailDrawer(false)}
                  className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                >
                  Close
                </button>
                {!selectedIncident.is_resolved && (
                  <button
                    onClick={() => {
                      handleResolve(selectedIncident.id);
                      setShowDetailDrawer(false);
                    }}
                    className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500"
                  >
                    Mark as Resolved
                  </button>
                )}
                <button
                  onClick={() => {
                    startEditing(selectedIncident);
                    setShowDetailDrawer(false);
                  }}
                  className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                >
                  Edit
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Incidents;
