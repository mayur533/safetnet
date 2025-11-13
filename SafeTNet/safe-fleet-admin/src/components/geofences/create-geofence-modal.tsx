'use client';

import { useState, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { geofencesService } from '@/lib/services/geofences';
import { organizationsService } from '@/lib/services/organizations';
import { authService } from '@/lib/services/auth';
import { usersService } from '@/lib/services/users';
import { toast } from 'sonner';
import { MapSelectorModal } from './map-selector-modal';
import { LoadingDots } from '@/components/ui/loading-dots';

interface CreateGeofenceModalProps {
  isOpen: boolean;
  onClose: () => void;
  onRefresh?: () => void;
}

interface Organization {
  id: number;
  name: string;
}

interface MapPoint {
  lat: number;
  lng: number;
}

export function CreateGeofenceModal({ isOpen, onClose, onRefresh }: CreateGeofenceModalProps) {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    organization: '',
  });

  const [mapPoints, setMapPoints] = useState<MapPoint[]>([]);
  const [isMapModalOpen, setIsMapModalOpen] = useState(false);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [currentUser, setCurrentUser] = useState<unknown>(null);

  // Fetch organizations when modal opens or set user's organization for Sub-Admins
  useEffect(() => {
    const fetchOrganizations = async () => {
      if (!isOpen) return;
      
      try {
        // Get current user from auth
        const currentUser = authService.getUser();
        if (!currentUser || !(currentUser as { id: number }).id) {
          console.error('No user found in auth');
          return;
        }
        
        // Fetch the current user's details from API to get organization info
        const userDetails = await usersService.getById((currentUser as { id: number }).id);
        setCurrentUser(userDetails);
        const isSubAdmin = userDetails?.role === 'SUB_ADMIN';
        
        if (isSubAdmin && userDetails?.organization) {
          // For Sub-Admins, use their own organization
          const org = userDetails.organization;
          setOrganizations([{ id: org.id, name: org.name }]);
          setFormData(prev => ({ ...prev, organization: org.id.toString() }));
        } else {
          // For Main Admin or users with organization field
          try {
            const orgs = await organizationsService.getAll();
            setOrganizations(orgs);
          } catch {
            // If API call fails (403), set empty organizations
            setOrganizations([]);
          }
        }
      } catch (error) {
        console.error('Failed to fetch organizations:', error);
        // Don't show error toast for Sub-Admins as they don't need to fetch orgs
      }
    };
    
    if (isOpen) {
      fetchOrganizations();
    }
  }, [isOpen]);

  const handleChange = (field: string, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
    if (errors[field]) {
      setErrors((prev) => ({ ...prev, [field]: '' }));
    }
  };

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Geofence name is required';
    }

    if (!formData.organization) {
      newErrors.organization = 'Please select an organization';
    }

    if (mapPoints.length < 3) {
      newErrors.polygon = 'Please select at least 3 points on the map to create a geofence';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleMapPointsConfirm = (points: MapPoint[]) => {
    setMapPoints(points);
    if (errors.polygon) {
      const newErrors = { ...errors };
      delete newErrors.polygon;
      setErrors(newErrors);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    if (isSubmitting) {
      return; // Prevent double submission
    }

    setIsSubmitting(true);

    try {
      // Create polygon from map points
      const coordinates = mapPoints.map(point => [point.lng, point.lat]);
      // Close the polygon by repeating the first point
      coordinates.push(coordinates[0]);
      
      const polygonJson = {
        type: 'Polygon',
        coordinates: [coordinates]
      };

      await geofencesService.create({
        name: formData.name,
        description: formData.description || undefined,
        polygon_json: polygonJson,
        organization: parseInt(formData.organization),
        active: true,
      });

      toast.success('Geofence created successfully!');
      
      // Reset form
      setFormData({
        name: '',
        description: '',
        organization: '',
      });
      setMapPoints([]);
      
      onClose();
      
      // Refresh geofences list
      if (onRefresh) onRefresh();
    } catch (error: unknown) {
      console.error('Create geofence error:', error);
      toast.error(error instanceof Error ? error.message : 'Failed to create geofence');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleClose = () => {
    setFormData({
      name: '',
      description: '',
      organization: '',
    });
    setMapPoints([]);
    setErrors({});
    onClose();
  };

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="sm:max-w-[600px] bg-card/95 backdrop-blur-xl border-border/50 max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="text-2xl font-bold flex items-center">
            <span className="material-icons text-indigo-600 mr-2">add_location</span>
            Create New Geofence
          </DialogTitle>
          <DialogDescription>
            Define a new security zone with custom boundaries and settings
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-5 mt-4">
          {/* Geofence Name */}
          <div className="space-y-2">
            <Label htmlFor="name" className="text-sm font-medium">
              Geofence Name <span className="text-red-500">*</span>
            </Label>
            <div className="relative">
              <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg">
                label
              </span>
              <Input
                id="name"
                type="text"
                placeholder="e.g., Downtown Security Zone"
                value={formData.name}
                onChange={(e) => handleChange('name', e.target.value)}
                className={`pl-10 ${errors.name ? 'border-red-500' : ''}`}
              />
            </div>
            {errors.name && <p className="text-xs text-red-500 mt-1">{errors.name}</p>}
          </div>

          {/* Description */}
          <div className="space-y-2">
            <Label htmlFor="description" className="text-sm font-medium">
              Description
            </Label>
            <div className="relative">
              <span className="material-icons absolute left-3 top-3 text-muted-foreground text-lg">
                description
              </span>
              <textarea
                id="description"
                placeholder="Optional description..."
                value={formData.description}
                onChange={(e) => handleChange('description', e.target.value)}
                className="w-full pl-10 pr-4 py-2 min-h-[80px] rounded-md border border-input bg-background text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              />
            </div>
          </div>

          {/* Organization */}
          {(() => {
            const org = organizations.find(org => org.id.toString() === formData.organization);
            const isSubAdmin = (currentUser as { role?: string })?.role === 'SUB_ADMIN';
            
            return (
              <div className="space-y-2">
                <Label htmlFor="organization" className="text-sm font-medium">
                  Organization <span className="text-red-500">*</span>
                </Label>
                <div className="relative">
                  <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg z-10">
                    business
                  </span>
                  {isSubAdmin ? (
                    <Input
                      value={org?.name || ''}
                      disabled
                      className="pl-10 bg-muted"
                    />
                  ) : (
                    <Select value={formData.organization} onValueChange={(value) => handleChange('organization', value)}>
                      <SelectTrigger className={`pl-10 ${errors.organization ? 'border-red-500' : ''}`}>
                        <SelectValue placeholder="Select organization" />
                      </SelectTrigger>
                      <SelectContent>
                        {organizations.map((org) => (
                          <SelectItem key={org.id} value={org.id.toString()}>
                            {org.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                </div>
                {errors.organization && <p className="text-xs text-red-500 mt-1">{errors.organization}</p>}
              </div>
            );
          })()}

          {/* Select Geofence Area */}
          <div className="space-y-3">
            <Label className="text-sm font-medium">
              Define Geofence Area <span className="text-red-500">*</span>
            </Label>
            
            <Button
              type="button"
              variant="outline"
              className={`w-full ${errors.polygon ? 'border-red-500' : ''}`}
              onClick={() => setIsMapModalOpen(true)}
            >
              <span className="material-icons text-lg mr-2">map</span>
              {mapPoints.length === 0 ? 'Select Geofence Area on Map' : `${mapPoints.length} Points Selected`}
            </Button>
            
            {mapPoints.length > 0 && (
              <div className="text-sm text-green-600 dark:text-green-400">
                <span className="material-icons text-sm mr-1">check_circle</span>
                {mapPoints.length} points selected
              </div>
            )}
            
            {errors.polygon && <p className="text-xs text-red-500 mt-1">{errors.polygon}</p>}
          </div>

          {/* Info Box */}
          <div className="bg-indigo-50 dark:bg-indigo-950/20 border border-indigo-200 dark:border-indigo-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <span className="material-icons text-indigo-600 text-xl">info</span>
              <div className="flex-1">
                <p className="text-sm text-indigo-900 dark:text-indigo-100 font-medium">
                  Drawing Tip
                </p>
                <p className="text-xs text-indigo-700 dark:text-indigo-300 mt-1">
                  Click the button above to open the map and select points by clicking on it. You can add as many points as needed.
                </p>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex justify-end space-x-3 pt-4 border-t">
            <Button
              type="button"
              variant="outline"
              onClick={handleClose}
              disabled={isSubmitting}
              className="px-6"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={isSubmitting}
              className="bg-indigo-600 hover:bg-indigo-700 text-white px-6"
            >
              {isSubmitting ? (
                <>
                  <LoadingDots />
                  <span className="ml-2">Creating</span>
                </>
              ) : (
                <>
                  <span className="material-icons text-sm mr-2">add_location</span>
                  Create Geofence
                </>
              )}
            </Button>
          </div>
        </form>
      </DialogContent>

      {/* Map Selector Modal */}
      <MapSelectorModal
        isOpen={isMapModalOpen}
        onClose={() => setIsMapModalOpen(false)}
        onConfirm={handleMapPointsConfirm}
      />
    </Dialog>
  );
}