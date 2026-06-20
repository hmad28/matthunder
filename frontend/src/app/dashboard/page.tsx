'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Target, Scan, AlertTriangle, FileText } from 'lucide-react'
import { api } from '@/lib/api'

interface DashboardStats {
  targets: number
  scans: number
  findings: number
  reports: number
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats>({
    targets: 0,
    scans: 0,
    findings: 0,
    reports: 0
  })

  useEffect(() => {
    loadStats()
  }, [])

  const loadStats = async () => {
    try {
      const [targets, scans, findings, reports] = await Promise.all([
        api.get('/api/v1/targets'),
        api.get('/api/v1/scans'),
        api.get('/api/v1/findings'),
        api.get('/api/v1/reports')
      ])
      
      setStats({
        targets: targets.data.length,
        scans: scans.data.length,
        findings: findings.data.length,
        reports: reports.data.length
      })
    } catch (error) {
      console.error('Failed to load stats:', error)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground mt-2">
          Overview of your bug hunting operations
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Targets</CardTitle>
            <Target className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.targets}</div>
            <p className="text-xs text-muted-foreground">
              Active targets being monitored
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
            <Scan className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.scans}</div>
            <p className="text-xs text-muted-foreground">
              Scans executed across all targets
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Findings</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.findings}</div>
            <p className="text-xs text-muted-foreground">
              Vulnerabilities discovered
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Reports</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.reports}</div>
            <p className="text-xs text-muted-foreground">
              Generated reports
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Recent Activity</CardTitle>
            <CardDescription>Latest scans and findings</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">
                No recent activity. Start by adding a target and running a scan.
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
            <CardDescription>Common operations</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <Link href="/targets" className="block w-full text-left px-4 py-2 rounded-md hover:bg-accent transition-colors">
                Add New Target
              </Link>
              <Link href="/scans" className="block w-full text-left px-4 py-2 rounded-md hover:bg-accent transition-colors">
                Run Deep Scan
              </Link>
              <Link href="/findings" className="block w-full text-left px-4 py-2 rounded-md hover:bg-accent transition-colors">
                View Findings
              </Link>
              <Link href="/reports" className="block w-full text-left px-4 py-2 rounded-md hover:bg-accent transition-colors">
                Generate Report
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
