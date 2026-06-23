'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { publicApi } from '@/lib/api'
import { 
  Activity, AlertTriangle, CheckCircle2, Clock, 
  Radio, Server, Shield, Zap, RefreshCw 
} from 'lucide-react'

interface SwarmMetrics {
  statistics: {
    total_targets: number
    total_entries: number
    active_entries: number
    critical_entries: number
    high_entries: number
    medium_entries: number
    low_entries: number
    finding_type_distribution: Record<string, number>
  }
  heatmap: Record<string, {
    concentration: number
    priority: string
    success_rate: number
    confidence: number
    is_expired: boolean
  }>
}

export default function SwarmPage() {
  const [metrics, setMetrics] = useState<SwarmMetrics | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadMetrics()
  }, [])

  const loadMetrics = async () => {
    try {
      const [metricsRes, matrixRes] = await Promise.all([
        publicApi.get('/api/v1/swarm/metrics'),
        publicApi.get('/api/v1/swarm/swarm-matrix')
      ])
      setMetrics(matrixRes.data)
    } catch (e) {
      console.error('Failed to load swarm data:', e)
      setMetrics(null)
    } finally {
      setLoading(false)
    }
  }

  const triggerDecay = async () => {
    try {
      await publicApi.post('/api/v1/swarm/decay')
      loadMetrics()
    } catch (e) {
      console.error('Failed to decay:', e)
    }
  }

  if (loading) return <div className="text-center py-12">Loading swarm data...</div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Swarm Intelligence</h1>
          <p className="text-muted-foreground mt-2">
            Pheromone-based agent coordination
          </p>
        </div>
        <Button variant="outline" onClick={loadMetrics}>
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      {metrics && (
        <>
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Server className="h-4 w-4" /> Active Targets
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{metrics.statistics.total_targets}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Activity className="h-4 w-4" /> Active Pheromones
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-blue-500">{metrics.statistics.active_entries}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4" /> Critical
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-red-500">{metrics.statistics.critical_entries}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Shield className="h-4 w-4" /> High Priority
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-orange-500">{metrics.statistics.high_entries}</div>
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-6 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Pheromone Heatmap</CardTitle>
                <CardDescription>Concentration levels for all active pheromones</CardDescription>
              </CardHeader>
              <CardContent>
                {Object.entries(metrics.heatmap).length === 0 ? (
                  <p className="text-muted-foreground text-center py-8">No active pheromones</p>
                ) : (
                  <div className="space-y-2">
                    {Object.entries(metrics.heatmap)
                      .sort(([, a], [, b]) => b.concentration - a.concentration)
                      .slice(0, 20)
                      .map(([key, entry]) => (
                        <div key={key} className="p-3 rounded-lg border border-border">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-sm font-medium truncate max-w-[200px]">{key}</span>
                            <div className="flex items-center gap-2">
                              <Badge className={
                                entry.priority === 'critical' ? 'bg-red-500/10 text-red-500' :
                                entry.priority === 'high' ? 'bg-orange-500/10 text-orange-500' :
                                entry.priority === 'medium' ? 'bg-yellow-500/10 text-yellow-500' :
                                'bg-blue-500/10 text-blue-500'
                              }>
                                {entry.priority}
                              </Badge>
                              <span className={`text-xs ${entry.is_expired ? 'text-red-400' : 'text-green-400'}`}>
                                {entry.is_expired ? 'Expired' : 'Active'}
                              </span>
                            </div>
                          </div>
                          <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            <span>τ: {entry.concentration.toFixed(2)}</span>
                            <span>Success: {(entry.success_rate * 100).toFixed(0)}%</span>
                            <span>Confidence: {(entry.confidence * 100).toFixed(0)}%</span>
                          </div>
                          <div className="w-full h-1.5 bg-muted rounded-full mt-1">
                            <div className="h-full rounded-full transition-all" style={{
                              width: `${entry.concentration * 100}%`,
                              background: entry.concentration > 0.7 ? 'rgb(239 68 68)' : 
                                          entry.concentration > 0.4 ? 'rgb(234 179 8)' : 
                                          'rgb(59 130 246)'
                            }} />
                          </div>
                        </div>
                      ))}
                  </div>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Finding Distribution</CardTitle>
                <CardDescription>Pheromone distribution by finding type</CardDescription>
              </CardHeader>
              <CardContent>
                {Object.entries(metrics.statistics.finding_type_distribution).length === 0 ? (
                  <p className="text-muted-foreground text-center py-8">No data available</p>
                ) : (
                  <div className="space-y-3">
                    {Object.entries(metrics.statistics.finding_type_distribution)
                      .sort(([, a], [, b]) => b - a)
                      .map(([type, count]) => (
                        <div key={type}>
                          <div className="flex justify-between text-sm mb-1">
                            <span className="capitalize">{type.replace(/_/g, ' ')}</span>
                            <span className="text-muted-foreground">{count}</span>
                          </div>
                          <div className="w-full h-2 bg-muted rounded-full">
                            <div className="h-full bg-primary rounded-full" style={{
                              width: `${(count / Math.max(...Object.values(metrics.statistics.finding_type_distribution))) * 100}%`
                            }} />
                          </div>
                        </div>
                      ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Actions</CardTitle>
            </CardHeader>
            <CardContent className="flex gap-3">
              <Button variant="outline" onClick={triggerDecay}>
                <Zap className="h-4 w-4 mr-2" /> Trigger Pheromone Decay
              </Button>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}