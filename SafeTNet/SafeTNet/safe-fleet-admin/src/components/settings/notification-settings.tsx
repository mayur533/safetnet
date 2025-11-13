'use client';

import { useState } from 'react';
import { Label } from '@/components/ui/label';

export function NotificationSettings() {
  const [emailAlerts, setEmailAlerts] = useState(true);
  const [pushNotifications, setPushNotifications] = useState(true);
  const [smsAlerts, setSmsAlerts] = useState(false);
  const [weeklyReports, setWeeklyReports] = useState(true);

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
        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-green-500 to-teal-600 flex items-center justify-center shadow-lg">
          <span className="material-icons text-white text-xl">notifications</span>
        </div>
        <div>
          <h3 className="font-semibold text-lg">Notification Settings</h3>
          <p className="text-xs text-muted-foreground">Control how you receive alerts</p>
        </div>
      </div>

      {/* Form */}
      <div className="space-y-5">
        {/* Email Alerts */}
        <div className="flex items-center justify-between">
          <div>
            <Label className="text-sm font-medium">Email Alerts</Label>
            <p className="text-xs text-muted-foreground mt-1">
              Receive security alerts via email
            </p>
          </div>
          <ToggleSwitch enabled={emailAlerts} onChange={() => setEmailAlerts(!emailAlerts)} />
        </div>

        {/* Push Notifications */}
        <div className="flex items-center justify-between pt-3 border-t border-border/50">
          <div>
            <Label className="text-sm font-medium">Push Notifications</Label>
            <p className="text-xs text-muted-foreground mt-1">
              Browser push notifications for real-time alerts
            </p>
          </div>
          <ToggleSwitch
            enabled={pushNotifications}
            onChange={() => setPushNotifications(!pushNotifications)}
          />
        </div>

        {/* SMS Alerts */}
        <div className="flex items-center justify-between pt-3 border-t border-border/50">
          <div>
            <Label className="text-sm font-medium">SMS Alerts</Label>
            <p className="text-xs text-muted-foreground mt-1">
              Critical alerts sent via text message
            </p>
          </div>
          <ToggleSwitch enabled={smsAlerts} onChange={() => setSmsAlerts(!smsAlerts)} />
        </div>

        {/* Weekly Reports */}
        <div className="flex items-center justify-between pt-3 border-t border-border/50">
          <div>
            <Label className="text-sm font-medium">Weekly Summary Reports</Label>
            <p className="text-xs text-muted-foreground mt-1">
              Receive weekly analytics digest
            </p>
          </div>
          <ToggleSwitch
            enabled={weeklyReports}
            onChange={() => setWeeklyReports(!weeklyReports)}
          />
        </div>

      </div>
    </div>
  );
}

