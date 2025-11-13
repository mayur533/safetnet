'use client';

import { useEffect, useState } from 'react';
import dynamic from 'next/dynamic';
import { Button } from '@/components/ui/button';
import { type Geofence } from '@/lib/services/geofences';

// Dynamic imports for Leaflet components (client-side only)
const MapContainer = dynamic(
  () => import('react-leaflet').then((mod) => mod.MapContainer),
  { ssr: false }
);

const TileLayer = dynamic(
  () => import('react-leaflet').then((mod) => mod.TileLayer),
  { ssr: false }
);

const Polygon = dynamic(
  () => import('react-leaflet').then((mod) => mod.Polygon),
  { ssr: false }
);

const Popup = dynamic(
  () => import('react-leaflet').then((mod) => mod.Popup),
  { ssr: false }
);

// Import MapController as a separate component
const MapController = dynamic(
  () => import('@/components/geofences/map-controller').then((mod) => mod.MapController),
  { ssr: false }
);

// Color palette for geofences
const colors = ['#6366f1', '#8b5cf6', '#06b6d4', '#10b981', '#f59e0b', '#ec4899', '#14b8a6', '#f97316'];

interface GeofencesMapProps {
  selectedGeofence: number | null;
  geofences: Geofence[];
  onSelectGeofence: (id: number | null) => void;
}

// Helper to extract coordinates from polygon_json
const extractCoordinates = (polygonJson: Record<string, unknown>): [number, number][] => {
  try {
    if (polygonJson.type === 'Polygon' && Array.isArray(polygonJson.coordinates)) {
      // GeoJSON format is [lng, lat] but Leaflet needs [lat, lng]
      const coords = polygonJson.coordinates[0] as number[][];
      return coords.map((coord: number[]) => [coord[1], coord[0]] as [number, number]);
    }
    return [];
  } catch (error) {
    console.error('Error extracting coordinates:', error);
    return [];
  }
};

export function GeofencesMap({ selectedGeofence, geofences, onSelectGeofence }: GeofencesMapProps) {
  const [isClient, setIsClient] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [mapCenter, setMapCenter] = useState<[number, number] | null>(null);

  useEffect(() => {
    setIsClient(true);
  }, []);

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

  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
  };

  // Assign colors to geofences
  const geofencesWithColors = geofences.map((geo, idx) => ({
    ...geo,
    color: colors[idx % colors.length],
    coordinates: extractCoordinates(geo.polygon_json as Record<string, unknown>)
  }));

  const zoomToGeofence = (geofence: typeof geofencesWithColors[0]) => {
    if (geofence.center_point) {
      setMapCenter([geofence.center_point[0], geofence.center_point[1]]);
      onSelectGeofence(geofence.id);
    }
  };

  // Calculate default map center (average of all center points)
  const defaultCenter: [number, number] = geofences.length > 0 && geofences[0].center_point
    ? [geofences[0].center_point[0], geofences[0].center_point[1]]
    : [40.7128, -74.0060]; // Default to NYC

  if (!isClient) {
    return (
      <div className="w-full h-full flex items-center justify-center bg-muted/20">
        <div className="text-center">
          <div className="animate-spin material-icons text-4xl text-indigo-600 mb-2">refresh</div>
          <p className="text-sm text-muted-foreground">Loading map...</p>
        </div>
      </div>
    );
  }

  // Use light theme tile layer (OpenStreetMap)
  const tileUrl = 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png';
  const attribution = '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors';

  return (
    <>
      <div className={`${
        isFullscreen 
          ? 'fixed inset-0 z-[999] bg-card' 
          : 'relative bg-card rounded-lg shadow-md border overflow-hidden'
      }`} style={{ 
        height: isFullscreen ? '100vh' : '600px',
        width: isFullscreen ? '100vw' : '100%',
        margin: 0,
        padding: 0
      }}>
      {/* Map */}
      <MapContainer
        center={defaultCenter}
        zoom={13}
        style={{ height: '100%', width: '100%' }}
        className="z-0"
      >
        <TileLayer
          url={tileUrl}
          attribution={attribution}
        />
        
        {/* Map Controller for zoom/pan */}
        {mapCenter && <MapController center={mapCenter} zoom={15} />}

        {/* Render all geofence polygons */}
        {geofencesWithColors.map((geofence) => {
          if (geofence.coordinates.length === 0) return null;

          return (
            <Polygon
              key={geofence.id}
              positions={geofence.coordinates}
              pathOptions={{
                color: geofence.color,
                fillColor: geofence.color,
                fillOpacity: selectedGeofence === geofence.id ? 0.5 : 0.3,
                weight: selectedGeofence === geofence.id ? 3 : 2,
              }}
              eventHandlers={{
                click: () => onSelectGeofence(geofence.id),
              }}
            >
              <Popup>
                <div className="p-2">
                  <h3 className="font-bold text-sm mb-1">{geofence.name}</h3>
                  {geofence.description && (
                    <p className="text-xs text-muted-foreground mb-2">{geofence.description}</p>
                  )}
                  <div className="space-y-1 text-xs">
                    <p className="flex items-center gap-1">
                      <span className="material-icons" style={{ fontSize: '12px' }}>business</span>
                      {geofence.organization_name}
                    </p>
                    <p className={`font-medium ${geofence.active ? 'text-green-600' : 'text-gray-600'}`}>
                      Status: {geofence.active ? 'Active' : 'Inactive'}
                    </p>
                  </div>
                </div>
              </Popup>
            </Polygon>
          );
        })}
      </MapContainer>

      {/* Fullscreen Button - Inside Map Container */}
      <Button
        onClick={toggleFullscreen}
        size="sm"
        variant="secondary"
        className={`absolute shadow-lg ${
          isFullscreen 
            ? 'top-4 right-4 z-[1000]' 
            : 'top-4 right-4 z-10'
        }`}
      >
        <span className="material-icons text-sm">
          {isFullscreen ? 'fullscreen_exit' : 'fullscreen'}
        </span>
      </Button>

      {/* Legend - Clickable (Show All) */}
      <div className={`absolute bottom-4 left-4 bg-card/95 backdrop-blur-sm p-3 rounded-lg shadow-lg border border-border/50 max-w-xs ${
        isFullscreen ? 'z-[1000]' : 'z-10'
      }`}>
        <h4 className="text-xs font-semibold mb-2 flex items-center gap-1">
          <span className="material-icons" style={{ fontSize: '14px' }}>layers</span>
          Active Geofences (Click to zoom)
        </h4>
        <div className="space-y-1 max-h-64 overflow-y-auto pr-2">
          {geofencesWithColors.filter(g => g.active).map((geo) => (
            <button
              key={geo.id}
              onClick={() => zoomToGeofence(geo)}
              className={`w-full flex items-center gap-2 text-xs p-1.5 rounded hover:bg-muted/50 transition-colors ${
                selectedGeofence === geo.id ? 'bg-muted' : ''
              }`}
            >
              <div
                className="w-3 h-3 rounded-full flex-shrink-0"
                style={{ backgroundColor: geo.color }}
              />
              <span className="truncate text-left">{geo.name}</span>
              {selectedGeofence === geo.id && (
                <span className="material-icons text-indigo-600 ml-auto" style={{ fontSize: '14px' }}>
                  gps_fixed
                </span>
              )}
            </button>
          ))}
        </div>
      </div>
    </div>
    </>
  );
}
