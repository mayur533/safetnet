'use client';

import { useState } from 'react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

const timezones = [
  'UTC',
  'America/New_York',
  'America/Los_Angeles',
  'Europe/London',
  'Asia/Tokyo',
  'Australia/Sydney',
];

const languages = [
  { code: 'en', name: 'English' },
  { code: 'es', name: 'Spanish' },
  { code: 'fr', name: 'French' },
  { code: 'de', name: 'German' },
  { code: 'ja', name: 'Japanese' },
];

export function GeneralSettings() {
  const [siteName, setSiteName] = useState('SafeFleet Admin Panel');
  const [timezone, setTimezone] = useState('America/New_York');
  const [language, setLanguage] = useState('en');

  return (
    <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6 pb-4 border-b border-border/50">
        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-indigo-500 to-blue-600 flex items-center justify-center shadow-lg">
          <span className="material-icons text-white text-xl">settings</span>
        </div>
        <div>
          <h3 className="font-semibold text-lg">General Settings</h3>
          <p className="text-xs text-muted-foreground">Basic application configuration</p>
        </div>
      </div>

      {/* Form */}
      <div className="space-y-5">
        {/* Site Name */}
        <div className="flex items-center justify-between">
          <Label htmlFor="siteName" className="text-sm font-medium">
            Site Name
          </Label>
          <div className="relative w-64">
            <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg">
              business
            </span>
            <Input
              id="siteName"
              type="text"
              value={siteName}
              onChange={(e) => setSiteName(e.target.value)}
              className="pl-10"
            />
          </div>
        </div>

        {/* Timezone */}
        <div className="flex items-center justify-between pt-3 border-t border-border/50">
          <Label htmlFor="timezone" className="text-sm font-medium">
            Timezone
          </Label>
          <div className="relative w-64">
            <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg z-10">
              schedule
            </span>
            <Select value={timezone} onValueChange={setTimezone}>
              <SelectTrigger className="pl-10">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {timezones.map((tz) => (
                  <SelectItem key={tz} value={tz}>
                    {tz}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        {/* Language */}
        <div className="flex items-center justify-between pt-3 border-t border-border/50">
          <Label htmlFor="language" className="text-sm font-medium">
            Language
          </Label>
          <div className="relative w-64">
            <span className="material-icons absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground text-lg z-10">
              language
            </span>
            <Select value={language} onValueChange={setLanguage}>
              <SelectTrigger className="pl-10">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {languages.map((lang) => (
                  <SelectItem key={lang.code} value={lang.code}>
                    {lang.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

      </div>
    </div>
  );
}

