'use client';

import { CardLoading } from '@/components/ui/content-loading';
import { type Geofence } from '@/lib/services/geofences';

interface GeofencesStatsProps {
  geofences: Geofence[];
  isLoading?: boolean;
}

export function GeofencesStats({ geofences, isLoading = false }: GeofencesStatsProps) {
  if (isLoading) {
    return <CardLoading count={3} />;
  }

  // Calculate stats from real geofences data
  const totalGeofences = geofences.length;
  const activeGeofences = geofences.filter(g => g.active).length;
  const inactiveGeofences = geofences.filter(g => !g.active).length;

  const stats = [
    {
      title: 'Total Geofences',
      value: totalGeofences,
      change: `${activeGeofences} active zones`,
      icon: 'public',
      gradient: 'from-indigo-500 to-purple-600',
    },
    {
      title: 'Active Zones',
      value: activeGeofences,
      change: 'Currently monitored',
      icon: 'check_circle',
      gradient: 'from-green-500 to-green-600',
      showPulse: true,
    },
    {
      title: 'Inactive Zones',
      value: inactiveGeofences,
      change: 'Disabled zones',
      icon: 'block',
      gradient: 'from-orange-500 to-red-600',
    },
  ];

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {stats.map((stat) => (
        <div
          key={stat.title}
          className={`bg-gradient-to-br ${stat.gradient} p-6 rounded-xl shadow-lg text-white relative overflow-hidden`}
        >
          {/* Background glow effect */}
          <div className="absolute top-0 right-0 w-32 h-32 bg-white/10 rounded-full blur-3xl"></div>
          
          <div className="relative z-10">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <p className="text-sm opacity-90 font-medium">{stat.title}</p>
                <div className="flex items-baseline gap-3 mt-2">
                  <h3 className="text-4xl font-bold">{stat.value}</h3>
                  {stat.showPulse && (
                    <div className="w-3 h-3 bg-white rounded-full animate-pulse"></div>
                  )}
                </div>
                <p className="text-xs mt-2 opacity-80">{stat.change}</p>
              </div>
              <div className="ml-4">
                <span
                  className="material-icons-outlined"
                  style={{ fontSize: '48px', opacity: 0.8 }}
                >
                  {stat.icon}
                </span>
              </div>
            </div>
          </div>

          {/* Bottom accent line */}
          <div className="absolute bottom-0 left-0 right-0 h-1 bg-white/30"></div>
        </div>
      ))}
    </div>
  );
}



