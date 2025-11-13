'use client';

import { useState } from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Button } from '@/components/ui/button';

interface LoginRecord {
  id: string;
  timestamp: string;
  ipAddress: string;
  device: string;
  location: string;
  status: 'success' | 'failed';
}

const loginHistory: LoginRecord[] = [
  {
    id: '1',
    timestamp: '2024-02-15 10:30:25',
    ipAddress: '192.168.1.100',
    device: 'Chrome on Windows',
    location: 'New York, USA',
    status: 'success',
  },
  {
    id: '2',
    timestamp: '2024-02-14 16:45:12',
    ipAddress: '192.168.1.100',
    device: 'Chrome on Windows',
    location: 'New York, USA',
    status: 'success',
  },
  {
    id: '3',
    timestamp: '2024-02-13 09:15:33',
    ipAddress: '192.168.1.105',
    device: 'Safari on macOS',
    location: 'New York, USA',
    status: 'success',
  },
  {
    id: '4',
    timestamp: '2024-02-12 14:20:18',
    ipAddress: '203.45.67.89',
    device: 'Chrome on Android',
    location: 'Unknown Location',
    status: 'failed',
  },
  {
    id: '5',
    timestamp: '2024-02-12 08:05:44',
    ipAddress: '192.168.1.100',
    device: 'Chrome on Windows',
    location: 'New York, USA',
    status: 'success',
  },
];

export function LoginHistory() {
  const [showAll, setShowAll] = useState(false);

  const displayedHistory = showAll ? loginHistory : loginHistory.slice(0, 5);

  const getStatusBadge = (status: 'success' | 'failed') => {
    if (status === 'success') {
      return (
        <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300">
          <span className="material-icons text-sm mr-1">check_circle</span>
          Success
        </span>
      );
    }
    return (
      <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300">
        <span className="material-icons text-sm mr-1">error</span>
        Failed
      </span>
    );
  };

  return (
    <div className="bg-card/50 backdrop-blur-xl p-6 rounded-2xl shadow-xl border border-border/50">
      {/* Header */}
      <div className="flex items-center justify-between mb-6 pb-4 border-b border-border/50">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-600 flex items-center justify-center shadow-lg">
            <span className="material-icons text-white text-xl">history</span>
          </div>
          <div>
            <h3 className="font-semibold text-lg">Login History</h3>
            <p className="text-xs text-muted-foreground">Recent account activity and sign-ins</p>
          </div>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setShowAll(!showAll)}
          className="text-xs"
        >
          {showAll ? 'Show Less' : 'Show All'}
        </Button>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-xl border border-border/50">
        <Table>
          <TableHeader>
            <TableRow className="border-b bg-muted/30 hover:bg-muted/30">
              <TableHead className="text-muted-foreground text-sm font-semibold">Timestamp</TableHead>
              <TableHead className="text-muted-foreground text-sm font-semibold">IP Address</TableHead>
              <TableHead className="text-muted-foreground text-sm font-semibold">Device</TableHead>
              <TableHead className="text-muted-foreground text-sm font-semibold">Location</TableHead>
              <TableHead className="text-muted-foreground text-sm font-semibold">Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {displayedHistory.map((record) => (
              <TableRow key={record.id} className="border-b hover:bg-muted/20 transition-colors">
                <TableCell className="py-3 px-4">
                  <div className="text-sm font-mono">{record.timestamp}</div>
                </TableCell>
                <TableCell className="py-3 px-4">
                  <div className="text-sm font-mono">{record.ipAddress}</div>
                </TableCell>
                <TableCell className="py-3 px-4">
                  <div className="flex items-center gap-2">
                    <span className="material-icons text-sm text-indigo-600">devices</span>
                    <span className="text-sm">{record.device}</span>
                  </div>
                </TableCell>
                <TableCell className="py-3 px-4">
                  <div className="flex items-center gap-2">
                    <span className="material-icons text-sm text-indigo-600">location_on</span>
                    <span className="text-sm">{record.location}</span>
                  </div>
                </TableCell>
                <TableCell className="py-3 px-4">{getStatusBadge(record.status)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      {/* Info */}
      <div className="mt-4 flex items-center justify-between text-xs text-muted-foreground">
        <p>Showing {displayedHistory.length} of {loginHistory.length} login attempts</p>
        <p>Last updated: 2 minutes ago</p>
      </div>
    </div>
  );
}

