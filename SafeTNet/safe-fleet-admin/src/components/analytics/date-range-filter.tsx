'use client';

import { useState } from 'react';

interface DateRangeFilterProps {
  dateRange: { from: Date; to: Date };
  onDateRangeChange: (range: { from: Date; to: Date }) => void;
}

export function DateRangeFilter({ dateRange, onDateRangeChange }: DateRangeFilterProps) {
  const [showMenu, setShowMenu] = useState(false);

  const presets = [
    { label: 'Last 7 Days', days: 7 },
    { label: 'Last 30 Days', days: 30 },
    { label: 'Last 90 Days', days: 90 },
    { label: 'This Year', days: 365 },
  ];

  const handlePreset = (days: number) => {
    const to = new Date();
    const from = new Date(new Date().setDate(to.getDate() - days));
    onDateRangeChange({ from, to });
    setShowMenu(false);
  };

  const formatDate = (date: Date) => {
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  };

  return (
    <div className="relative">
      <button
        onClick={() => setShowMenu(!showMenu)}
        className="flex items-center gap-2 px-4 py-2 bg-background border border-border rounded-lg hover:bg-muted transition-colors"
      >
        <span className="material-icons text-lg">date_range</span>
        <span className="text-sm font-medium">
          {formatDate(dateRange.from)} - {formatDate(dateRange.to)}
        </span>
        <span className="material-icons text-sm">expand_more</span>
      </button>

      {showMenu && (
        <div className="absolute right-0 mt-2 w-56 bg-card border border-border rounded-lg shadow-lg z-10">
          <div className="p-2">
            <div className="px-3 py-2 text-xs font-semibold text-muted-foreground uppercase">
              Quick Select
            </div>
            {presets.map((preset) => (
              <button
                key={preset.label}
                onClick={() => handlePreset(preset.days)}
                className="w-full text-left px-3 py-2 rounded-md text-sm transition-colors hover:bg-muted"
              >
                {preset.label}
              </button>
            ))}

            <div className="border-t border-border my-2"></div>

            <div className="px-3 py-2">
              <label className="text-xs text-muted-foreground block mb-1">From</label>
              <input
                type="date"
                className="w-full px-2 py-1 text-xs bg-background border border-border rounded"
                value={dateRange.from.toISOString().split('T')[0]}
                onChange={(e) =>
                  onDateRangeChange({
                    ...dateRange,
                    from: new Date(e.target.value),
                  })
                }
              />
            </div>

            <div className="px-3 py-2">
              <label className="text-xs text-muted-foreground block mb-1">To</label>
              <input
                type="date"
                className="w-full px-2 py-1 text-xs bg-background border border-border rounded"
                value={dateRange.to.toISOString().split('T')[0]}
                onChange={(e) =>
                  onDateRangeChange({
                    ...dateRange,
                    to: new Date(e.target.value),
                  })
                }
              />
            </div>

            <div className="p-2">
              <button
                onClick={() => setShowMenu(false)}
                className="w-full px-3 py-2 text-xs bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
              >
                Apply
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
























