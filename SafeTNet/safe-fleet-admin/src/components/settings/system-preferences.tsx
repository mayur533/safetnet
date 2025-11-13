'use client';

import { useState } from 'react';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

const refreshRates = [
  { value: '5', label: '5 seconds' },
  { value: '10', label: '10 seconds' },
  { value: '30', label: '30 seconds' },
  { value: '60', label: '1 minute' },
  { value: '300', label: '5 minutes' },
];

export function SystemPreferences() {
  const [theme, setTheme] = useState<'light' | 'dark' | 'system'>('system');
  const [refreshRate, setRefreshRate] = useState('30');
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const handleThemeChange = (newTheme: 'light' | 'dark' | 'system') => {
    setTheme(newTheme);
    // In real app, this would update the theme
    if (newTheme === 'dark') {
      document.documentElement.classList.add('dark');
    } else if (newTheme === 'light') {
      document.documentElement.classList.remove('dark');
    } else {
      // System preference
      const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      if (isDark) {
        document.documentElement.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
      }
    }
  };

  const ToggleSwitch = ({ enabled, onChange }: { enabled: boolean; onChange: () => void }) => (
    <button
      onClick={onChange}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
        enabled ? 'bg-indigo-600' : 'bg-gray-300 dark:bg-gray-600'
      }`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
          enabled ? 'translate-x-6' : 'translate-x-1'
        }`}
      />
    </button>
  );

  return (
    <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6 pb-4 border-b border-border/50">
        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center shadow-lg">
          <span className="material-icons text-white text-xl">tune</span>
        </div>
        <div>
          <h3 className="font-semibold text-lg">System Preferences</h3>
          <p className="text-xs text-muted-foreground">Customize your dashboard experience</p>
        </div>
      </div>

      {/* Form */}
      <div className="space-y-5">
        {/* Theme Toggle */}
        <div className="flex items-center justify-between">
          <Label className="text-sm font-medium">Theme</Label>
          <div className="flex gap-2">
            <button
              onClick={() => handleThemeChange('light')}
              className={`px-3 py-2 rounded-lg text-xs font-medium transition-all flex items-center gap-2 ${
                theme === 'light'
                  ? 'bg-gradient-to-r from-indigo-600 to-blue-600 text-white shadow-lg'
                  : 'bg-background border border-border hover:bg-muted'
              }`}
            >
              <span className="material-icons text-base">light_mode</span>
              light
            </button>
            <button
              onClick={() => handleThemeChange('dark')}
              className={`px-3 py-2 rounded-lg text-xs font-medium transition-all flex items-center gap-2 ${
                theme === 'dark'
                  ? 'bg-gradient-to-r from-indigo-600 to-blue-600 text-white shadow-lg'
                  : 'bg-background border border-border hover:bg-muted'
              }`}
            >
              <span className="material-icons text-base">dark_mode</span>
              dark
            </button>
            <button
              onClick={() => handleThemeChange('system')}
              className={`px-3 py-2 rounded-lg text-xs font-medium transition-all flex items-center gap-2 ${
                theme === 'system'
                  ? 'bg-gradient-to-r from-indigo-600 to-blue-600 text-white shadow-lg'
                  : 'bg-background border border-border hover:bg-muted'
              }`}
            >
              <span className="material-icons text-base">settings_brightness</span>
              system
            </button>
          </div>
        </div>

        {/* Dashboard Refresh Rate */}
        <div className="flex items-center justify-between pt-3 border-t border-border/50">
          <Label htmlFor="refreshRate" className="text-sm font-medium">
            Dashboard Refresh Rate
          </Label>
          <div className="relative w-64">
            <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg z-10">
              refresh
            </span>
            <Select value={refreshRate} onValueChange={setRefreshRate}>
              <SelectTrigger className="pl-10">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {refreshRates.map((rate) => (
                  <SelectItem key={rate.value} value={rate.value}>
                    {rate.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Auto Refresh */}
        <div className="flex items-center justify-between pt-3 border-t border-border/50">
          <div>
            <Label className="text-sm font-medium">Auto Refresh</Label>
            <p className="text-xs text-muted-foreground mt-1">
              Automatically refresh dashboard data
            </p>
          </div>
          <ToggleSwitch enabled={autoRefresh} onChange={() => setAutoRefresh(!autoRefresh)} />
        </div>

        {/* Sound Effects */}
        <div className="flex items-center justify-between pt-3 border-t border-border/50">
          <div>
            <Label className="text-sm font-medium">Sound Effects</Label>
            <p className="text-xs text-muted-foreground mt-1">
              Play sounds for alerts and notifications
            </p>
          </div>
          <ToggleSwitch enabled={soundEnabled} onChange={() => setSoundEnabled(!soundEnabled)} />
        </div>

      </div>
    </div>
  );
}

