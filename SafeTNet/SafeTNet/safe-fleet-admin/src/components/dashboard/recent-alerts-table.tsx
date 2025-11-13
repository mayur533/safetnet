'use client';

import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from '@tanstack/react-table';
import { useDashboardStore, type Alert } from '@/lib/stores/dashboard';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

const columnHelper = createColumnHelper<Alert>();

const getStatusBadge = (status: Alert['status']) => {
  switch (status) {
    case 'pending':
      return (
        <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-300">
          Pending
        </Badge>
      );
    case 'critical':
      return (
        <Badge className="bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-300">
          Critical
        </Badge>
      );
    case 'resolved':
      return (
        <Badge className="bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-300">
          Resolved
        </Badge>
      );
    default:
      return null;
  }
};

export function RecentAlertsTable() {
  const { alerts } = useDashboardStore();

  const columns = [
    columnHelper.accessor('time', {
      header: 'Time',
      cell: (info) => (
        <div className="font-medium text-sm">{info.getValue()}</div>
      ),
    }),
    columnHelper.accessor('location', {
      header: 'Location',
      cell: (info) => (
        <div className="text-sm">{info.getValue()}</div>
      ),
    }),
    columnHelper.accessor('type', {
      header: 'Type',
      cell: (info) => (
        <div className="text-sm">{info.getValue()}</div>
      ),
    }),
    columnHelper.accessor('status', {
      header: 'Status',
      cell: (info) => getStatusBadge(info.getValue()),
    }),
    columnHelper.display({
      id: 'actions',
      header: '',
      cell: () => (
        <div className="flex justify-end">
          <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
            <span className="material-icons-outlined text-base text-muted-foreground hover:text-primary">
              more_vert
            </span>
          </Button>
        </div>
      ),
    }),
  ];

  const table = useReactTable({
    data: alerts,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  return (
    <div className="lg:col-span-4 bg-card p-6 rounded-lg shadow-md border">
      <h3 className="font-semibold mb-4 text-lg">Recent Security Alerts</h3>
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id} className="border-b">
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id} className="text-muted-foreground text-sm font-medium">
                    {header.isPlaceholder
                      ? null
                      : flexRender(
                          header.column.columnDef.header,
                          header.getContext()
                        )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows?.length ? (
              table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  className="border-b hover:bg-muted/50 transition-colors"
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id} className="py-3 px-4">
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext()
                      )}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="h-32 text-center text-muted-foreground"
                >
                  <div className="flex flex-col items-center gap-2">
                    <span className="material-icons text-5xl">notifications_off</span>
                    <p className="text-sm">No recent alerts</p>
                    <p className="text-xs">Security alerts will appear here</p>
                  </div>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
