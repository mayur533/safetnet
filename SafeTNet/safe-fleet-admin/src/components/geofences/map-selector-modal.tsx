'use client';

import { useState, useEffect } from 'react';
import dynamic from 'next/dynamic';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import { useMapEvents } from 'react-leaflet';

// Dynamic imports for Leaflet components (client-side only)
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

const Polygon = dynamic(
  () => import('react-leaflet').then((mod) => mod.Polygon),
  { ssr: false }
);

// Component to handle map click events
function ClickHandler({ onMapClick }: { onMapClick: (lat: number, lng: number) => void }) {
  useMapEvents({
    click: (e) => {
      const { lat, lng } = e.latlng;
      onMapClick(lat, lng);
    },
  });
  return null;
}

interface MapPoint {
  lat: number;
  lng: number;
}

interface MapSelectorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (points: MapPoint[]) => void;
}

export function MapSelectorModal({
  isOpen,
  onClose,
  onConfirm,
}: MapSelectorModalProps) {
  const [mapPoints, setMapPoints] = useState<MapPoint[]>([]);
  const [isClient, setIsClient] = useState(false);

  useEffect(() => {
    setIsClient(true);
  }, []);

  useEffect(() => {
    if (!isOpen) {
      setMapPoints([]);
    }
  }, [isOpen]);

  const handleMapClick = (lat: number, lng: number) => {
    setMapPoints(prev => [...prev, { lat, lng }]);
  };

  const removeLastPoint = () => {
    if (mapPoints.length === 0) return;
    setMapPoints(prev => prev.slice(0, -1));
  };

  const clearAllPoints = () => {
    setMapPoints([]);
  };

  const handleConfirm = () => {
    if (mapPoints.length < 3) {
      toast.error('At least 3 points are required to create a geofence');
      return;
    }
    onConfirm(mapPoints);
    onClose();
  };

  const handleClose = () => {
    setMapPoints([]);
    onClose();
  };

  // Convert points to Leaflet polygon format [lat, lng][]
  const getPolygonCoordinates = () => {
    return mapPoints.map(point => [point.lat, point.lng]);
  };

  if (!isClient) {
    return null;
  }

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="max-w-4xl max-h-[90vh]">
        <DialogHeader>
          <DialogTitle>Select Geofence Area</DialogTitle>
          <DialogDescription>
            Click on the map to add points. At least 3 points are required.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Map Controls */}
          <div className="flex items-center justify-between">
            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={removeLastPoint}
                disabled={mapPoints.length === 0}
              >
                <span className="material-icons text-sm mr-2">undo</span>
                Remove Last
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={clearAllPoints}
                disabled={mapPoints.length === 0}
              >
                <span className="material-icons text-sm mr-2">clear_all</span>
                Clear All
              </Button>
            </div>
            <div className="text-sm text-muted-foreground">
              Points added: <strong>{mapPoints.length}</strong>
            </div>
          </div>

          {/* Map */}
          <div className="border rounded-lg overflow-hidden" style={{ height: '450px' }}>
            <MapContainer
              center={[28.6139, 77.2090]} // Delhi coordinates
              zoom={12}
              style={{ height: '100%', width: '100%' }}
              className="z-0"
            >
              <TileLayer
                url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
              />
              
              <ClickHandler onMapClick={handleMapClick} />

              {/* Render markers for each point */}
              {mapPoints.map((point, index) => (
                <Marker
                  key={`${point.lat}-${point.lng}-${index}`}
                  position={[point.lat, point.lng]}
                  interactive={false}
                />
              ))}

              {/* Render polygon if we have at least 3 points */}
              {mapPoints.length >= 3 && (
                <Polygon
                  positions={getPolygonCoordinates() as [number, number][]}
                  pathOptions={{
                    color: '#FF0000',
                    fillColor: '#FF0000',
                    fillOpacity: 0.35,
                    weight: 2,
                  }}
                  interactive={false}
                />
              )}
            </MapContainer>
          </div>

          {/* Instructions */}
          <div className="bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <span className="material-icons text-blue-600 text-xl">info</span>
              <div className="text-sm text-blue-900 dark:text-blue-100">
                <p className="font-medium">Instructions:</p>
                <ul className="list-disc list-inside mt-1 space-y-1">
                  <li>Click on the map to add points for your geofence</li>
                  <li>At least 3 points are required to create a polygon</li>
                  <li>You can remove the last point or clear all points and start over</li>
                  <li>Click &quot;Confirm&quot; when you&apos;re done selecting points</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex justify-end space-x-2">
            <Button type="button" variant="outline" onClick={handleClose}>
              Cancel
            </Button>
            <Button
              type="button"
              onClick={handleConfirm}
              disabled={mapPoints.length < 3}
              className="bg-indigo-600 hover:bg-indigo-700"
            >
              Confirm ({mapPoints.length} points)
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
