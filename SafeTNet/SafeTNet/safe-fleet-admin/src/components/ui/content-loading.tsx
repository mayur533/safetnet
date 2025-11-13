import React from 'react';

interface ContentLoadingProps {
  text?: string;
  className?: string;
}

export function ContentLoading({ text = 'Loading...', className = '' }: ContentLoadingProps) {
  return (
    <div className={`flex flex-col items-center justify-center py-12 ${className}`}>
      <div className="relative">
        {/* Spinning circle */}
        <div className="w-12 h-12 border-4 border-primary/20 border-t-primary rounded-full animate-spin"></div>
        {/* Inner pulse */}
        <div className="absolute inset-0 w-12 h-12 border-4 border-primary/10 rounded-full animate-pulse"></div>
      </div>
      <p className="mt-4 text-sm text-muted-foreground animate-pulse">{text}</p>
    </div>
  );
}

interface ListLoadingProps {
  rows?: number;
  className?: string;
}

export function ListLoading({ rows = 3, className = '' }: ListLoadingProps) {
  return (
    <div className={`space-y-4 ${className}`}>
      {Array.from({ length: rows }).map((_, index) => (
        <div
          key={index}
          className="flex items-start space-x-4 p-6 rounded-lg bg-muted/20 animate-pulse"
          style={{ animationDelay: `${index * 100}ms` }}
        >
          {/* Icon/Avatar skeleton */}
          <div className="flex-shrink-0 w-12 h-12 bg-muted rounded-lg"></div>
          
          {/* Content skeleton */}
          <div className="flex-1 space-y-3">
            <div className="flex items-center justify-between">
              <div className="h-4 w-32 bg-muted rounded"></div>
              <div className="h-3 w-20 bg-muted/60 rounded"></div>
            </div>
            <div className="h-3 w-full bg-muted/60 rounded"></div>
            <div className="h-3 w-3/4 bg-muted/40 rounded"></div>
          </div>
        </div>
      ))}
    </div>
  );
}

interface FormLoadingProps {
  fields?: number;
  className?: string;
}

export function FormLoading({ fields = 4, className = '' }: FormLoadingProps) {
  return (
    <div className={`space-y-4 ${className}`}>
      {Array.from({ length: fields }).map((_, index) => (
        <div
          key={index}
          className="space-y-2 animate-pulse"
          style={{ animationDelay: `${index * 80}ms` }}
        >
          <div className="h-4 w-24 bg-muted rounded"></div>
          <div className="h-10 w-full bg-muted/60 rounded-lg"></div>
        </div>
      ))}
    </div>
  );
}

interface TableLoadingProps {
  rows?: number;
  columns?: number;
}

export function TableLoading({ rows = 5, columns = 5 }: TableLoadingProps) {
  return (
    <div className="space-y-3 animate-pulse">
      {/* Header skeleton */}
      <div className="flex space-x-4 border-b pb-3">
        {Array.from({ length: columns }).map((_, i) => (
          <div key={i} className="flex-1 h-4 bg-muted rounded"></div>
        ))}
      </div>
      
      {/* Rows skeleton */}
      {Array.from({ length: rows }).map((_, rowIndex) => (
        <div key={rowIndex} className="flex space-x-4 py-3">
          {Array.from({ length: columns }).map((_, colIndex) => (
            <div
              key={colIndex}
              className="flex-1 h-4 bg-muted/60 rounded"
              style={{ animationDelay: `${(rowIndex * columns + colIndex) * 50}ms` }}
            ></div>
          ))}
        </div>
      ))}
    </div>
  );
}

interface CardLoadingProps {
  count?: number;
  className?: string;
}

export function CardLoading({ count = 4, className = '' }: CardLoadingProps) {
  const gridCols = count === 3 ? 'lg:grid-cols-3' : 'lg:grid-cols-4';
  return (
    <div className={`grid grid-cols-1 md:grid-cols-2 ${gridCols} gap-6 ${className}`}>
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          className="bg-card p-6 rounded-lg shadow-md border animate-pulse"
          style={{ animationDelay: `${i * 100}ms` }}
        >
          <div className="flex items-center justify-between mb-4">
            <div className="h-4 w-24 bg-muted rounded"></div>
            <div className="w-10 h-10 bg-gradient-to-br from-muted to-muted/60 rounded-full"></div>
          </div>
          <div className="h-8 w-16 bg-muted rounded mb-2"></div>
          <div className="h-3 w-32 bg-muted/60 rounded"></div>
        </div>
      ))}
    </div>
  );
}

