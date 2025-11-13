'use client';

import { useEffect, useState } from 'react';
import dynamic from 'next/dynamic';
import { geofencesService } from '@/lib/services/geofences';
import { toast } from 'sonner';

// Dynamically import MapContainer to avoid SSR issues
const MapContainer = dynamic(
  () => import('react-leaflet').then((mod) => mod.MapContainer),
  { ssr: false }
);

const TileLayer = dynamic(
  () => import('react-leaflet').then((mod) => mod.TileLayer),
  { ssr: false }
);

const Marker = dynamic(
  () => import('react-leaflet').then((mod) => mod.Marker),
  { ssr: false }
);

const Popup = dynamic(
  () => import('react-leaflet').then((mod) => mod.Popup),
  { ssr: false }
);

interface Geofence {
  id: number;
  name: string;
  polygon_json: unknown;
  center_point?: unknown;
  active: boolean;
  organization_name?: string;
}

export function GeofencesMap() {
  const [isClient, setIsClient] = useState(false);
  const [isDarkMode, setIsDarkMode] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [geofences, setGeofences] = useState<Geofence[]>([]);
  const [loading, setLoading] = useState(true);

  // Handle body overflow when fullscreen
  useEffect(() => {
    if (isFullscreen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }
    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isFullscreen]);

  useEffect(() => {
    setIsClient(true);
    fetchGeofences();
    
    // Detect application theme
    const checkTheme = () => {
      const hasDarkClass = document.documentElement.classList.contains('dark');
      setIsDarkMode(hasDarkClass);
    };

    checkTheme();

    // Watch for theme changes
    const observer = new MutationObserver(checkTheme);
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class'],
    });

    return () => {
      observer.disconnect();
    };
  }, []);

  const fetchGeofences = async () => {
    try {
      setLoading(true);
      const data = await geofencesService.getAll();
      setGeofences(data.filter(g => g.active)); // Only show active geofences
    } catch (error) {
      console.error('Error fetching geofences:', error);
      toast.error('Failed to fetch geofences');
    } finally {
      setLoading(false);
    }
  };

  // Get marker position from geofence (use center_point)
  const getMarkerPosition = (geofence: Geofence): [number, number] | null => {
    try {
      // Use center_point if available (it's an array [lat, lng])
      if (Array.isArray(geofence.center_point) && geofence.center_point.length === 2) {
        return [geofence.center_point[0], geofence.center_point[1]];
      }
      return null;
    } catch (error) {
      console.error('Error getting marker position:', error);
      return null;
    }
  };

  // Calculate map center
  const mapCenter: [number, number] = loading || geofences.length === 0
    ? [40.7128, -74.0060] // NYC default
    : (getMarkerPosition(geofences[0]) || [40.7128, -74.0060]);

  if (!isClient) {
    return (
      <div className="lg:col-span-2 bg-card p-6 rounded-lg shadow-md border">
        <h3 className="font-semibold mb-4 text-lg">Geofences Overview</h3>
        <div className="relative h-96 bg-muted rounded-md overflow-hidden flex items-center justify-center">
          <div className="text-muted-foreground">Loading map...</div>
        </div>
      </div>
    );
  }

  return (
    <div className={`${
      isFullscreen 
        ? 'fixed inset-0 z-[999] bg-card flex flex-col' 
        : 'lg:col-span-2 bg-card pt-2 pb-6 px-6 rounded-lg shadow-md border overflow-hidden relative'
    }`}>
      {/* Map Header - Compact */}
      <div className={`flex items-center justify-between ${
        isFullscreen ? 'px-6 py-4 border-b border-border flex-shrink-0' : 'mb-2'
      }`}>
        <h3 className="font-semibold text-sm">Geofences Overview</h3>
        
        {/* Fullscreen Button in Header */}
        <button
          onClick={() => setIsFullscreen(!isFullscreen)}
          className="p-1.5 hover:bg-muted rounded transition-colors"
          title={isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}
        >
          <span className="material-icons text-base text-muted-foreground hover:text-foreground">
            {isFullscreen ? 'fullscreen_exit' : 'fullscreen'}
          </span>
        </button>
      </div>
      
      <div 
        className={`relative overflow-hidden ${
          isFullscreen ? 'flex-1' : 'h-96 rounded-md'
        }`}
      >

        {loading ? (
          <div className="h-full flex items-center justify-center bg-muted/20">
            <div className="text-muted-foreground animate-pulse">Loading geofences...</div>
          </div>
        ) : (
          <MapContainer
            center={mapCenter}
            zoom={geofences.length > 0 ? 12 : 2}
            style={{ height: '100%', width: '100%', backgroundColor: isDarkMode ? '#0f172a' : '#e5e7eb' }}
            className="z-0"
          >
            <TileLayer
              url={
                isDarkMode
                  ? "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
                  : "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
              }
              attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
            />
            {geofences.map((geofence) => {
              const position = getMarkerPosition(geofence);
              if (!position) return null;

              return (
                <Marker key={geofence.id} position={position}>
                  <Popup>
                    <div className="text-center">
                      <span className="material-icons text-primary" style={{ fontSize: '20px' }}>
                        location_on
                      </span>
                      <p className="text-sm font-medium mt-1">{geofence.name}</p>
                      {geofence.organization_name && (
                        <p className="text-xs text-muted-foreground mt-1">
                          {geofence.organization_name}
                        </p>
                      )}
                    </div>
                  </Popup>
                </Marker>
              );
            })}
          </MapContainer>
        )}
      </div>
    </div>
  );
}
