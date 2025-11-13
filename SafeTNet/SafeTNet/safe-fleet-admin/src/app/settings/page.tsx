'use client';

import { useState } from 'react';
import { GeneralSettings } from '@/components/settings/general-settings';
import { NotificationSettings } from '@/components/settings/notification-settings';
import { SystemPreferences } from '@/components/settings/system-preferences';
import { Button } from '@/components/ui/button';
import { LoadingDots } from '@/components/ui/loading-dots';

export default function SettingsPage() {
  const [isSaving, setIsSaving] = useState(false);

  const handleSaveAll = () => {
    setIsSaving(true);
    setTimeout(() => {
      setIsSaving(false);
      alert('All settings saved successfully!');
    }, 1000);
  };

  return (
    <div className="space-y-6">
      {/* Header Section */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Settings</h1>
          <p className="text-muted-foreground mt-1">Manage your application preferences and configuration</p>
        </div>
      </div>

      {/* Settings Sections - Full Width */}
      <div className="space-y-6">
        {/* General Settings */}
        <GeneralSettings />

        {/* Notification Settings */}
        <NotificationSettings />

        {/* System Preferences */}
        <SystemPreferences />
      </div>

      {/* Global Save Button */}
      <div className="flex justify-end pt-4">
        <Button
          onClick={handleSaveAll}
          disabled={isSaving}
          className="bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-700 hover:to-blue-700 text-white px-8 py-2.5 shadow-lg hover:shadow-xl transition-all"
        >
          {isSaving ? (
            <>
              <LoadingDots />
              <span className="ml-2">Saving All Changes</span>
            </>
          ) : (
            <>
              <span className="material-icons text-sm mr-2">save</span>
              Save All Changes
            </>
          )}
        </Button>
      </div>
    </div>
  );
}

