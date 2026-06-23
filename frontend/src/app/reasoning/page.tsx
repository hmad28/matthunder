'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { publicApi } from '@/lib/api'
import { 
  TreePine, Play, Square, RotateCcw, AlertTriangle, 
  CheckCircle2, Clock, ArrowRight, Loader2 
} from 'lucide-react'

interface PTNode {
  id: string
  type: string
  title: string
  status: string
  risk_level: string
  children: string[]
  dependencies: string[]
  description?: string
  scanners?: string[]
  estimated_time?: number
}

interface TreeData {
  root: string
  nodes: PTNode[]
  progress: number
  total_nodes: number
  completed_nodes: number
  pending_nodes: number
}

export default function ReasoningPage() {
  const [treeData, setTreeData] = useState<TreeData | null>(null)
  const [scanId, setScanId] = useState('')
  const [loading, setLoading] = useState(false)
  const [generating, setGenerating] = useState(false)

  const loadTree = async () => {
    if (!scanId.trim()) return
    setLoading(true)
    try {
      const res = await publicApi.get(`/api/v1/reasoning/ptt/${scanId}`)
      setTreeData(res.data)
    } catch (e) {
      console.error('Failed to load tree:', e)
    } finally {
      setLoading(false)
    }
  }

  const generateTree = async () => {
    if (!scanId.trim()) return
    setGenerating(true)
    try {
      await publicApi.post('/api/v1/reasoning/ptt/generate', {
        target_id: scanId,
        scan_id: `scan_${Date.now()}`,
        finding_type: 'reconnaissance',
        reconnaissance_data: {}
      })
      await loadTree()
    } catch (e) {
      console.error('Failed to generate tree:', e)
    } finally {
      setGenerating(false)
    }
  }

  const getStatusIcon = (status: string) => {
    switch(status) {
      case 'completed': return <CheckCircle2 className="h-4 w-4 text-green-500" />
      case 'running': return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />
      case 'backtracked': return <RotateCcw className="h-4 w-4 text-yellow-500" />
      default: return <Clock className="h-4 w-4 text-muted-foreground" />
    }
  }

  const getRiskBadge = (risk: string) => {
    const colors = {
      critical: 'bg-red-500/10 text-red-500',
      high: 'bg-orange-500/10 text-orange-500', 
      medium: 'bg-yellow-500/10 text-yellow-500',
      low: 'bg-blue-500/10 text-blue-500'
    }
    return <Badge className={colors[risk as keyof typeof colors] || colors.low}>{risk}</Badge>
  }

  const renderNode = (nodeId: string, depth: number = 0) => {
    const node = treeData?.nodes.find(n => n.id === nodeId)
    if (!node) return null

    return (
      <div key={node.id} style={{ marginLeft: depth * 24 }} className="mb-2">
        <div className={`p-3 rounded-lg border ${
          node.status === 'completed' ? 'border-green-500/20 bg-green-500/5' :
          node.status === 'running' ? 'border-blue-500/20 bg-blue-500/5' :
          node.status === 'backtracked' ? 'border-yellow-500/20 bg-yellow-500/5' :
          'border-border bg-card'
        }`}>
          <div className="flex items-center gap-2">
            {getStatusIcon(node.status)}
            <span className="font-medium text-sm">{node.title}</span>
            {getRiskBadge(node.risk_level)}
            <Badge variant="outline" className="text-xs">{node.type}</Badge>
          </div>
          {node.description && (
            <p className="text-xs text-muted-foreground mt-1 ml-6">{node.description}</p>
          )}
          {node.scanners && node.scanners.length > 0 && (
            <div className="flex gap-1 mt-1 ml-6">
              {node.scanners.map(s => (
                <Badge key={s} variant="secondary" className="text-xs">{s}</Badge>
              ))}
            </div>
          )}
        </div>
        {node.children.map(childId => renderNode(childId, depth + 1))}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Reasoning Engine</h1>
        <p className="text-muted-foreground mt-2">
          Pentesting Task Tree - AI-driven attack planning
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>PTT Generator</CardTitle>
          <CardDescription>Generate or load Pentesting Task Tree</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2">
            <input
              type="text"
              value={scanId}
              onChange={e => setScanId(e.target.value)}
              placeholder="Enter target domain or scan ID..."
              className="flex-1 px-4 py-2 rounded-md border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring"
            />
            <Button onClick={generateTree} disabled={generating || !scanId.trim()}>
              {generating ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" /> Generating</> : <><TreePine className="h-4 w-4 mr-2" /> Generate</>}
            </Button>
            <Button variant="outline" onClick={loadTree} disabled={loading || !scanId.trim()}>
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Load
            </Button>
          </div>
        </CardContent>
      </Card>

      {treeData && (
        <>
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Progress</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{treeData.progress}%</div>
                <div className="w-full h-2 bg-muted rounded-full mt-2">
                  <div className="h-full bg-primary rounded-full transition-all" style={{width: `${treeData.progress}%`}} />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Total Nodes</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{treeData.total_nodes}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Completed</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-green-500">{treeData.completed_nodes}</div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Pending</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold text-yellow-500">{treeData.pending_nodes}</div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Task Tree</CardTitle>
              <CardDescription>Visual breakdown of pentesting tasks</CardDescription>
            </CardHeader>
            <CardContent>
              {renderNode(treeData.root)}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  )
}