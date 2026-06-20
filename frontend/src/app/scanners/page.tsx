'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { api } from '@/lib/api'

interface Scanner {
  name: string
  display_name: string
  description: string
  category: string
  is_active: boolean
}

export default function ScannersPage() {
  const [scanners, setScanners] = useState<Scanner[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedScanner, setSelectedScanner] = useState('')
  const [target, setTarget] = useState('')
  const [running, setRunning] = useState(false)

  useEffect(() => {
    loadScanners()
  }, [])

  const loadScanners = async () => {
    try {
      const response = await api.get('/api/v1/scanners')
      setScanners(response.data)
    } catch (error) {
      console.error('Failed to load scanners:', error)
    } finally {
      setLoading(false)
    }
  }

  const runScanner = async () => {
    if (!selectedScanner || !target) return
    
    setRunning(true)
    try {
      await api.post(`/api/v1/scanners/${selectedScanner}/run`, {
        target: target,
        config: {}
      })
      alert('Scanner started!')
      setTarget('')
    } catch (error) {
      console.error('Failed to run scanner:', error)
      alert('Failed to run scanner')
    } finally {
      setRunning(false)
    }
  }

  const getCategoryColor = (category: string) => {
    switch (category) {
      case 'vuln': return 'bg-red-500/10 text-red-500'
      case 'discovery': return 'bg-blue-500/10 text-blue-500'
      case 'infra': return 'bg-green-500/10 text-green-500'
      case 'recon': return 'bg-purple-500/10 text-purple-500'
      default: return 'bg-muted text-muted-foreground'
    }
  }

  if (loading) {
    return <div className="text-center py-12">Loading scanners...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Scanners</h1>
        <p className="text-muted-foreground mt-2">
          Run individual vulnerability scanners
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Run Scanner</CardTitle>
          <CardDescription>Select a scanner and target</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">Scanner</label>
              <select
                value={selectedScanner}
                onChange={(e) => setSelectedScanner(e.target.value)}
                className="w-full mt-1 px-4 py-2 rounded-md border border-input bg-background"
              >
                <option value="">Select a scanner</option>
                {scanners.map((scanner) => (
                  <option key={scanner.name} value={scanner.name}>
                    {scanner.display_name}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-sm font-medium">Target Domain</label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com"
                className="w-full mt-1 px-4 py-2 rounded-md border border-input bg-background"
              />
            </div>

            <Button
              onClick={runScanner}
              disabled={!selectedScanner || !target || running}
              className="w-full"
            >
              {running ? 'Running...' : 'Run Scanner'}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Available Scanners ({scanners.length})</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {scanners.map((scanner) => (
              <div
                key={scanner.name}
                className="p-4 rounded-lg border border-border hover:bg-accent/50 transition-colors"
              >
                <div className="flex items-start justify-between mb-2">
                  <h3 className="font-medium">{scanner.display_name}</h3>
                  <span className={`px-2 py-1 rounded text-xs ${getCategoryColor(scanner.category)}`}>
                    {scanner.category}
                  </span>
                </div>
                <p className="text-sm text-muted-foreground">
                  {scanner.description}
                </p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
