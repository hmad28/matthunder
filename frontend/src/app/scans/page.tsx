'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Play, Square, Loader2 } from 'lucide-react'
import { publicApi, api } from '@/lib/api'

interface Scan {
  id: string
  target_id: string
  scan_type: string
  status: string
  speed: string
  created_at: string
  started_at: string | null
  completed_at: string | null
}

interface Target {
  id: string
  domain: string
}

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([])
  const [targets, setTargets] = useState<Target[]>([])
  const [selectedTarget, setSelectedTarget] = useState('')
  const [scanType, setScanType] = useState('deep')
  const [speed, setSpeed] = useState('standard')
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      const [scansRes, targetsRes] = await Promise.all([
        publicApi.get('/api/v1/public/scans'),
        publicApi.get('/api/v1/public/targets')
      ])
      setScans(scansRes.data)
      setTargets(targetsRes.data)
    } catch (error) {
      console.error('Failed to load data:', error)
    } finally {
      setLoading(false)
    }
  }

  const startScan = async () => {
    if (!selectedTarget) return

    setStarting(true)
    try {
      await api.post('/api/v1/scans', {
        target_id: selectedTarget,
        scan_type: scanType,
        speed: speed
      })
      loadData()
    } catch (error) {
      console.error('Failed to start scan:', error)
    } finally {
      setStarting(false)
    }
  }

  const stopScan = async (scanId: string) => {
    try {
      await api.post(`/api/v1/scans/${scanId}/stop`)
      loadData()
    } catch (error) {
      console.error('Failed to stop scan:', error)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-500'
      case 'running': return 'text-blue-500'
      case 'failed': return 'text-red-500'
      case 'cancelled': return 'text-yellow-500'
      default: return 'text-muted-foreground'
    }
  }

  if (loading) {
    return <div className="text-center py-12">Loading scans...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Scans</h1>
        <p className="text-muted-foreground mt-2">
          Run and monitor security scans
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Start New Scan</CardTitle>
          <CardDescription>Configure and launch a new scan</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <label htmlFor="scan-target" className="text-sm font-medium">Target</label>
              <select
                id="scan-target"
                value={selectedTarget}
                onChange={(e) => setSelectedTarget(e.target.value)}
                className="w-full mt-1 px-4 py-2 rounded-md border border-input bg-background"
              >
                <option value="">Select a target</option>
                {targets.map((target) => (
                  <option key={target.id} value={target.id}>
                    {target.domain}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label htmlFor="scan-type" className="text-sm font-medium">Scan Type</label>
              <select
                id="scan-type"
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
                className="w-full mt-1 px-4 py-2 rounded-md border border-input bg-background"
              >
                <option value="light">Light Scan</option>
                <option value="dark">Dark Scan</option>
                <option value="deep">Deep Scan</option>
                <option value="pipeline">Full Pipeline</option>
              </select>
            </div>

            <div>
              <label htmlFor="scan-speed" className="text-sm font-medium">Speed</label>
              <select
                id="scan-speed"
                value={speed}
                onChange={(e) => setSpeed(e.target.value)}
                className="w-full mt-1 px-4 py-2 rounded-md border border-input bg-background"
              >
                <option value="low">Low</option>
                <option value="standard">Standard</option>
                <option value="fast">Fast</option>
              </select>
            </div>

            <Button
              onClick={startScan}
              disabled={!selectedTarget || starting}
              className="w-full"
            >
              {starting ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Starting...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4 mr-2" />
                  Start Scan
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Scan History ({scans.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {scans.length === 0 ? (
            <p className="text-center text-muted-foreground py-8">
              No scans yet. Start your first scan above.
            </p>
          ) : (
            <div className="space-y-2">
              {scans.map((scan) => (
                <div
                  key={scan.id}
                  data-testid="scan-history-row"
                  className="flex items-center justify-between p-4 rounded-lg border border-border"
                >
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{scan.scan_type}</span>
                      <span className={`text-xs ${getStatusColor(scan.status)}`}>
                        {scan.status}
                      </span>
                    </div>
                    <div className="text-sm text-muted-foreground mt-1">
                      Speed: {scan.speed} / Started {new Date(scan.created_at).toLocaleString()}
                    </div>
                  </div>
                  {scan.status === 'running' && (
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => stopScan(scan.id)}
                    >
                      <Square className="h-4 w-4 mr-2" />
                      Stop
                    </Button>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}