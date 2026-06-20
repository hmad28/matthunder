'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Play, CheckCircle, Circle, Loader2 } from 'lucide-react'
import { api } from '@/lib/api'

interface Target {
  id: string
  domain: string
}

const PIPELINE_PHASES = [
  { name: 'passive_recon', label: 'Passive Reconnaissance', description: 'Subfinder + Assetfinder', icon: '🔍' },
  { name: 'active_recon', label: 'Active Reconnaissance', description: 'Httpx + Port Scan + WAF + Tech', icon: '🎯' },
  { name: 'content_discovery', label: 'Content Discovery', description: 'Gau + Katana + JS Analysis + Fuzzer', icon: '🕷️' },
  { name: 'automated_scanning', label: 'Automated Scanning', description: 'Nuclei (CVEs, exposures, misconfigs)', icon: '🔬' },
  { name: 'vulnerability_scan', label: 'Vulnerability Scan', description: 'SQLi + XSS + LFI + CORS + SSTI + SSRF', icon: '⚡' },
  { name: 'intel_discovery', label: 'Intel & Discovery', description: 'BLH + 3rd Party + Cred + GraphQL', icon: '🧠' },
]

export default function PipelinePage() {
  const [targets, setTargets] = useState<Target[]>([])
  const [selectedTarget, setSelectedTarget] = useState('')
  const [speed, setSpeed] = useState('standard')
  const [running, setRunning] = useState(false)
  const [pipelineStatus, setPipelineStatus] = useState<any>(null)

  useEffect(() => {
    loadTargets()
  }, [])

  const loadTargets = async () => {
    try {
      const response = await api.get('/api/v1/targets')
      setTargets(response.data)
    } catch (error) {
      console.error('Failed to load targets:', error)
    }
  }

  const runPipeline = async () => {
    if (!selectedTarget) return
    
    setRunning(true)
    try {
      const response = await api.post('/api/v1/pipeline/run', {
        target_id: selectedTarget,
        speed: speed
      })
      setPipelineStatus(response.data)
    } catch (error) {
      console.error('Failed to run pipeline:', error)
      alert('Failed to start pipeline')
    } finally {
      setRunning(false)
    }
  }

  const getPhaseStatus = (phaseName: string) => {
    if (!pipelineStatus) return 'pending'
    if (pipelineStatus.completed_phases?.includes(phaseName)) return 'done'
    if (pipelineStatus.current_phase === phaseName) return 'running'
    return 'pending'
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Pipeline</h1>
        <p className="text-muted-foreground mt-2">
          6-phase automated reconnaissance pipeline
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Run Pipeline</CardTitle>
          <CardDescription>Execute the full automated scanning pipeline</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">Target</label>
              <select
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
              <label className="text-sm font-medium">Speed</label>
              <select
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
              onClick={runPipeline}
              disabled={!selectedTarget || running}
              className="w-full"
            >
              {running ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Starting...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4 mr-2" />
                  Run Full Pipeline
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Pipeline Phases</CardTitle>
          <CardDescription>Visual progress of the 6-phase pipeline</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {PIPELINE_PHASES.map((phase, index) => {
              const status = getPhaseStatus(phase.name)
              return (
                <div
                  key={phase.name}
                  className={`flex items-center gap-4 p-4 rounded-lg border transition-colors ${
                    status === 'done'
                      ? 'border-green-500/50 bg-green-500/5'
                      : status === 'running'
                      ? 'border-blue-500/50 bg-blue-500/5'
                      : 'border-border'
                  }`}
                >
                  <div className="flex-shrink-0">
                    {status === 'done' ? (
                      <CheckCircle className="h-8 w-8 text-green-500" />
                    ) : status === 'running' ? (
                      <Loader2 className="h-8 w-8 text-blue-500 animate-spin" />
                    ) : (
                      <Circle className="h-8 w-8 text-muted-foreground" />
                    )}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-2xl">{phase.icon}</span>
                      <h3 className="font-medium">{phase.label}</h3>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      {phase.description}
                    </p>
                  </div>
                  <div className="text-sm text-muted-foreground">
                    Phase {index + 1}
                  </div>
                </div>
              )
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
