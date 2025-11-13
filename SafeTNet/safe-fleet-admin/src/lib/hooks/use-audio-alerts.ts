'use client';

import { useCallback } from 'react';
import { toast } from 'sonner';

export function useAudioAlerts() {
  const playAlert = useCallback((type: 'critical' | 'warning' | 'info') => {
    // Create audio context for emergency alerts
    const audioContext = new (window.AudioContext || (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext)();
    
    // Different frequencies for different alert types
    const frequencies = {
      critical: 800, // High frequency for critical alerts
      warning: 600,  // Medium frequency for warnings
      info: 400,     // Lower frequency for info
    };

    const oscillator = audioContext.createOscillator();
    const gainNode = audioContext.createGain();

    oscillator.connect(gainNode);
    gainNode.connect(audioContext.destination);

    oscillator.frequency.setValueAtTime(frequencies[type], audioContext.currentTime);
    oscillator.type = 'sine';

    // Set volume based on alert type
    const volumes = {
      critical: 0.8,
      warning: 0.6,
      info: 0.4,
    };

    gainNode.gain.setValueAtTime(volumes[type], audioContext.currentTime);

    // Create a beep pattern
    oscillator.start(audioContext.currentTime);
    oscillator.stop(audioContext.currentTime + 0.2);

    // Show toast notification
    const messages = {
      critical: 'Critical alert detected!',
      warning: 'Warning alert triggered',
      info: 'Information alert',
    };

    const toastTypes = {
      critical: 'error' as const,
      warning: 'warning' as const,
      info: 'info' as const,
    };

    toast[toastTypes[type]](messages[type], {
      duration: type === 'critical' ? 5000 : 3000,
      action: {
        label: 'Dismiss',
        onClick: () => console.log('Alert dismissed'),
      },
    });
  }, []);

  const playEmergencyAlert = useCallback(() => {
    playAlert('critical');
  }, [playAlert]);

  const playWarningAlert = useCallback(() => {
    playAlert('warning');
  }, [playAlert]);

  const playInfoAlert = useCallback(() => {
    playAlert('info');
  }, [playAlert]);

  return {
    playEmergencyAlert,
    playWarningAlert,
    playInfoAlert,
    playAlert,
  };
}



