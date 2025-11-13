'use client';

import { useEffect } from 'react';
import { useMap } from 'react-leaflet';

interface MapControllerProps {
  center: [number, number] | null;
  zoom?: number;
}

export function MapController({ center, zoom }: MapControllerProps) {
  const map = useMap();
  
  useEffect(() => {
    if (center && map) {
      map.setView(center, zoom || 15, { animate: true, duration: 1 });
    }
  }, [center, zoom, map]);

  return null;
}





















