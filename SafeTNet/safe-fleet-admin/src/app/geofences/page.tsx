'use client';

import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { GeofencesMap } from '@/components/geofences/geofences-map';
import { GeofencesSidebar } from '@/components/geofences/geofences-sidebar';
import { ContentLoading } from '@/components/ui/content-loading';
import { geofencesService, type Geofence } from '@/lib/services/geofences';

export default function GeofencesPage() {
  const [selectedGeofence, setSelectedGeofence] = useState<number | null>(null);
  const [geofences, setGeofences] = useState<Geofence[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    fetchGeofences();
  }, []);

  const fetchGeofences = async () => {
    try {
      setIsLoading(true);
      const data = await geofencesService.getAll();
      setGeofences(data);
    } catch (error: unknown) {
      console.error('Error fetching geofences:', error);
      toast.error('Failed to load geofences');
    } finally {
      setIsLoading(false);
    }
  };

  // const selectedGeo = geofences.find(g => g.id === selectedGeofence);

  if (isLoading) {
    return (
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground">Geofence Overview</h1>
            <p className="text-muted-foreground mt-1">Monitor security zones across organizations</p>
          </div>
        </div>

        {/* Stats Loading */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-24 bg-muted/60 rounded-lg animate-pulse"></div>
          ))}
        </div>

        {/* Map and Sidebar Loading */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          <div className="lg:col-span-3 bg-card rounded-lg shadow-md border overflow-hidden" style={{ height: '600px' }}>
            <ContentLoading text="Loading map..." />
          </div>
          <div className="lg:col-span-1 bg-card rounded-lg shadow-md border p-4">
            <div className="space-y-4 animate-pulse">
              <div className="h-6 w-32 bg-muted rounded"></div>
              <div className="space-y-3">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div key={i} className="h-16 bg-muted/60 rounded-lg"></div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Geofence Overview</h1>
          <p className="text-muted-foreground mt-1">Monitor all security zones across organizations (View Only)</p>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-gradient-to-br from-indigo-500 to-indigo-600 p-4 rounded-lg shadow-lg text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-indigo-100">Total Geofences</p>
              <h3 className="text-2xl font-bold mt-1">{geofences.length}</h3>
            </div>
            <span className="material-icons opacity-80" style={{ fontSize: '36px' }}>
              map
            </span>
          </div>
        </div>

        <div className="bg-gradient-to-br from-green-500 to-green-600 p-4 rounded-lg shadow-lg text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-green-100">Active Zones</p>
              <h3 className="text-2xl font-bold mt-1">
                {geofences.filter(g => g.active).length}
              </h3>
            </div>
            <span className="material-icons opacity-80" style={{ fontSize: '36px' }}>
              check_circle
            </span>
          </div>
        </div>

        <div className="bg-gradient-to-br from-gray-500 to-gray-600 p-4 rounded-lg shadow-lg text-white">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-100">Inactive Zones</p>
              <h3 className="text-2xl font-bold mt-1">
                {geofences.filter(g => !g.active).length}
              </h3>
            </div>
            <span className="material-icons opacity-80" style={{ fontSize: '36px' }}>
              block
            </span>
          </div>
        </div>
      </div>

      {/* Map and Sidebar Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Map - 3/4 width */}
        <div className="lg:col-span-3">
          <GeofencesMap
            selectedGeofence={selectedGeofence}
            geofences={geofences}
            onSelectGeofence={setSelectedGeofence}
          />
        </div>

        {/* Sidebar - 1/4 width (Right side) */}
        <div className="lg:col-span-1">
          <GeofencesSidebar
            selectedGeofence={selectedGeofence}
            onSelectGeofence={setSelectedGeofence}
            geofences={geofences}
            onRefresh={fetchGeofences}
          />
        </div>
      </div>
    </div>
  );
}
