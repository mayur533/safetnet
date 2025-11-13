import React, { useState, useEffect } from 'react';
import { officerService, geofenceService } from '../services/api';
import { SecurityOfficer, Geofence } from '../types';
import { Users, Plus, Edit, Trash2, Phone, Mail, MapPin } from 'lucide-react';

interface OfficerFormData {
  username: string;
  name: string;
  contact: string;
  email: string;
  password: string;
  confirmPassword: string;
  assigned_geofence: number | '';
  is_active: boolean;
}

const Officers: React.FC = () => {
  const [officers, setOfficers] = useState<SecurityOfficer[]>([]);
  const [geofences, setGeofences] = useState<Geofence[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [editingOfficer, setEditingOfficer] = useState<SecurityOfficer | null>(null);
  const [formData, setFormData] = useState<OfficerFormData>({
    username: '',
    name: '',
    contact: '',
    email: '',
    password: '',
    confirmPassword: '',
    assigned_geofence: '',
    is_active: true
  });

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [officersResponse, geofencesResponse] = await Promise.all([
        officerService.getOfficers(),
        geofenceService.getGeofences()
      ]);
      setOfficers(officersResponse.results);
      setGeofences(geofencesResponse.results);
    } catch (err: any) {
      setError(err.message || 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Validate required fields for new officers
    if (!editingOfficer) {
      if (!formData.username || !formData.username.trim()) {
        setError('Username is required');
        return;
      }
      if (!formData.password) {
        setError('Password is required');
        return;
      }
      if (formData.password.length < 6) {
        setError('Password must be at least 6 characters');
        return;
      }
      if (formData.password !== formData.confirmPassword) {
        setError('Passwords do not match');
        return;
      }
    }
    
    const submitData: any = {
      ...formData,
      assigned_geofence: formData.assigned_geofence || undefined
    };
    
    // Only include password and username when creating new officer
    if (!editingOfficer) {
      submitData.username = formData.username;
      submitData.password = formData.password;
    } else {
      // Remove password fields when editing
      delete submitData.password;
      delete submitData.confirmPassword;
      delete submitData.username; // Username cannot be changed
    }

    try {
      if (editingOfficer) {
        await officerService.updateOfficer(editingOfficer.id, submitData);
      } else {
        await officerService.createOfficer(submitData);
      }
      
      setShowForm(false);
      setEditingOfficer(null);
      setFormData({ username: '', name: '', contact: '', email: '', password: '', confirmPassword: '', assigned_geofence: '', is_active: true });
      fetchData();
    } catch (err: any) {
      setError(err.message || 'Failed to save officer');
    }
  };

  const handleDelete = async (id: number) => {
    if (window.confirm('Are you sure you want to delete this officer?')) {
      try {
        await officerService.deleteOfficer(id);
        fetchData();
      } catch (err: any) {
        setError(err.message || 'Failed to delete officer');
      }
    }
  };

  const startEditing = (officer: SecurityOfficer) => {
    setEditingOfficer(officer);
    setFormData({
      username: (officer as any).username || '',
      name: officer.name,
      contact: officer.contact,
      email: officer.email || '',
      password: '',
      confirmPassword: '',
      assigned_geofence: officer.assigned_geofence || '',
      is_active: officer.is_active
    });
    setShowForm(true);
  };

  const toggleOfficerStatus = async (officer: SecurityOfficer) => {
    try {
      await officerService.updateOfficer(officer.id, { is_active: !officer.is_active });
      fetchData();
    } catch (err: any) {
      setError(err.message || 'Failed to update officer status');
    }
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
          <h1 className="text-2xl font-bold text-gray-900">Security Officers</h1>
          <p className="mt-1 text-sm text-gray-500">
            Manage your security officers and their assignments
          </p>
        </div>
        <button
          onClick={() => setShowForm(true)}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
        >
          <Plus className="h-4 w-4 mr-2" />
          Add Officer
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

      {/* Officers Grid */}
      <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {officers.map((officer) => (
          <div key={officer.id} className="bg-white overflow-hidden shadow rounded-lg">
            <div className="p-6">
              <div className="flex items-center">
                <div className="flex-shrink-0">
                  <div className={`h-12 w-12 rounded-full flex items-center justify-center ${
                    officer.is_active ? 'bg-green-100' : 'bg-gray-100'
                  }`}>
                    <Users className={`h-6 w-6 ${
                      officer.is_active ? 'text-green-600' : 'text-gray-400'
                    }`} />
                  </div>
                </div>
                <div className="ml-4 flex-1">
                  <h3 className="text-lg font-medium text-gray-900">{officer.name}</h3>
                  <div className="flex items-center mt-1">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                      officer.is_active 
                        ? 'bg-green-100 text-green-800' 
                        : 'bg-red-100 text-red-800'
                    }`}>
                      {officer.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                </div>
              </div>
              
              <div className="mt-4 space-y-2">
                <div className="flex items-center text-sm text-gray-500">
                  <Phone className="h-4 w-4 mr-2" />
                  {officer.contact}
                </div>
                {officer.email && (
                  <div className="flex items-center text-sm text-gray-500">
                    <Mail className="h-4 w-4 mr-2" />
                    {officer.email}
                  </div>
                )}
                {officer.assigned_geofence_name && (
                  <div className="flex items-center text-sm text-gray-500">
                    <MapPin className="h-4 w-4 mr-2" />
                    {officer.assigned_geofence_name}
                  </div>
                )}
              </div>
              
              <div className="mt-4 flex justify-between items-center">
                <div className="flex space-x-2">
                  <button
                    onClick={() => startEditing(officer)}
                    className="text-primary-600 hover:text-primary-900"
                  >
                    <Edit className="h-4 w-4" />
                  </button>
                  <button
                    onClick={() => handleDelete(officer.id)}
                    className="text-red-600 hover:text-red-900"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </div>
                <button
                  onClick={() => toggleOfficerStatus(officer)}
                  className={`px-3 py-1 text-xs font-medium rounded-full ${
                    officer.is_active
                      ? 'bg-red-100 text-red-800 hover:bg-red-200'
                      : 'bg-green-100 text-green-800 hover:bg-green-200'
                  }`}
                >
                  {officer.is_active ? 'Deactivate' : 'Activate'}
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Form Modal */}
      {showForm && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border w-11/12 max-w-md shadow-lg rounded-md bg-white">
            <div className="mt-3">
              <h3 className="text-lg font-medium text-gray-900 mb-4">
                {editingOfficer ? 'Edit Officer' : 'Add New Officer'}
              </h3>
              
              <form onSubmit={handleSubmit} className="space-y-4">
                {!editingOfficer && (
                  <div>
                    <label htmlFor="username" className="block text-sm font-medium text-gray-700">
                      Username *
                    </label>
                    <input
                      type="text"
                      id="username"
                      required={!editingOfficer}
                      value={formData.username}
                      onChange={(e) => setFormData(prev => ({ ...prev, username: e.target.value }))}
                      className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                      placeholder="Enter unique username"
                    />
                  </div>
                )}
                {editingOfficer && (
                  <div>
                    <label htmlFor="username" className="block text-sm font-medium text-gray-700">
                      Username
                    </label>
                    <input
                      type="text"
                      id="username"
                      value={formData.username}
                      disabled
                      className="mt-1 block w-full border-gray-300 rounded-md shadow-sm bg-gray-100 cursor-not-allowed sm:text-sm"
                    />
                    <p className="mt-1 text-xs text-gray-500">Username cannot be changed after creation</p>
                  </div>
                )}
                <div>
                  <label htmlFor="name" className="block text-sm font-medium text-gray-700">
                    Name *
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
                  <label htmlFor="contact" className="block text-sm font-medium text-gray-700">
                    Contact *
                  </label>
                  <input
                    type="text"
                    id="contact"
                    required
                    value={formData.contact}
                    onChange={(e) => setFormData(prev => ({ ...prev, contact: e.target.value }))}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                    placeholder="Phone number"
                  />
                </div>

                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                    Email
                  </label>
                  <input
                    type="email"
                    id="email"
                    value={formData.email}
                    onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                  />
                </div>

                {!editingOfficer && (
                  <>
                    <div>
                      <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                        Password *
                      </label>
                      <input
                        type="password"
                        id="password"
                        required={!editingOfficer}
                        value={formData.password}
                        onChange={(e) => setFormData(prev => ({ ...prev, password: e.target.value }))}
                        className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                        placeholder="Minimum 6 characters"
                      />
                    </div>

                    <div>
                      <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-700">
                        Confirm Password *
                      </label>
                      <input
                        type="password"
                        id="confirmPassword"
                        required={!editingOfficer}
                        value={formData.confirmPassword}
                        onChange={(e) => setFormData(prev => ({ ...prev, confirmPassword: e.target.value }))}
                        className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                        placeholder="Re-enter password"
                      />
                    </div>
                  </>
                )}

                <div>
                  <label htmlFor="assigned_geofence" className="block text-sm font-medium text-gray-700">
                    Assigned Geofence
                  </label>
                  <select
                    id="assigned_geofence"
                    value={formData.assigned_geofence}
                    onChange={(e) => setFormData(prev => ({ ...prev, assigned_geofence: e.target.value ? Number(e.target.value) : '' }))}
                    className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                  >
                    <option value="">No assignment</option>
                    {geofences.map((geofence) => (
                      <option key={geofence.id} value={geofence.id}>
                        {geofence.name}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="flex items-center">
                  <input
                    id="is_active"
                    type="checkbox"
                    checked={formData.is_active}
                    onChange={(e) => setFormData(prev => ({ ...prev, is_active: e.target.checked }))}
                    className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  />
                  <label htmlFor="is_active" className="ml-2 block text-sm text-gray-900">
                    Active
                  </label>
                </div>

                <div className="flex justify-end space-x-3 pt-4">
                  <button
                    type="button"
                    onClick={() => {
                      setShowForm(false);
                      setEditingOfficer(null);
                      setFormData({ username: '', name: '', contact: '', email: '', password: '', confirmPassword: '', assigned_geofence: '', is_active: true });
                    }}
                    className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
                  >
                    {editingOfficer ? 'Update' : 'Create'} Officer
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

export default Officers;
