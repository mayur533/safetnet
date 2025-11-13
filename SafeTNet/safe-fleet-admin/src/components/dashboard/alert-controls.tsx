'use client';

import { Button } from '@/components/ui/button';
import { useAudioAlerts } from '@/lib/hooks/use-audio-alerts';

export function AlertControls() {
  const { playEmergencyAlert, playWarningAlert, playInfoAlert } = useAudioAlerts();

  return (
    <div className="mb-6 p-4 bg-muted/50 rounded-lg border">
      <h4 className="font-medium mb-3">Test Alert System</h4>
      <div className="flex gap-3">
        <Button
          onClick={playEmergencyAlert}
          variant="destructive"
          size="sm"
        >
          Test Critical Alert
        </Button>
        <Button
          onClick={playWarningAlert}
          variant="outline"
          size="sm"
          className="border-yellow-500 text-yellow-600 hover:bg-yellow-50"
        >
          Test Warning Alert
        </Button>
        <Button
          onClick={playInfoAlert}
          variant="outline"
          size="sm"
          className="border-blue-500 text-blue-600 hover:bg-blue-50"
        >
          Test Info Alert
        </Button>
      </div>
    </div>
  );
}



