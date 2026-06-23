import { cn } from '@/lib/utils'

interface SkeletonProps {
  className?: string
}

export function Skeleton({ className }: SkeletonProps) {
  return (
    <div
      className={cn('animate-pulse rounded-md bg-muted', className)}
    />
  )
}

export function CardSkeleton() {
  return (
    <div className="rounded-lg border bg-card p-6 space-y-3">
      <Skeleton className="h-4 w-1/4" />
      <Skeleton className="h-8 w-3/4" />
      <Skeleton className="h-4 w-1/2" />
    </div>
  )
}

export function TableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-2">
      {/* Header */}
      <div className="flex gap-4 p-4 border-b">
        <Skeleton className="h-4 w-1/5" />
        <Skeleton className="h-4 w-1/5" />
        <Skeleton className="h-4 w-1/5" />
        <Skeleton className="h-4 w-1/5" />
        <Skeleton className="h-4 w-1/5" />
      </div>
      {/* Rows */}
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4 p-4">
          <Skeleton className="h-4 w-1/5" />
          <Skeleton className="h-4 w-1/5" />
          <Skeleton className="h-4 w-1/5" />
          <Skeleton className="h-4 w-1/5" />
          <Skeleton className="h-4 w-1/5" />
        </div>
      ))}
    </div>
  )
}

export function ListSkeleton({ items = 3 }: { items?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: items }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 p-4 border rounded-lg">
          <Skeleton className="h-10 w-10 rounded-full" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-3 w-1/2" />
          </div>
        </div>
      ))}
    </div>
  )
}

export function ScanLogSkeleton() {
  return (
    <div className="space-y-2 font-mono text-sm">
      {Array.from({ length: 10 }).map((_, i) => (
        <div key={i} className="flex gap-2">
          <Skeleton className="h-4 w-20" />
          <Skeleton className="h-4 flex-1" />
        </div>
      ))}
    </div>
  )
}
