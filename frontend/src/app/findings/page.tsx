'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { api } from '@/lib/api'

interface Finding {
  id: string
  scan_id: string
  scanner: string
  severity: string
  category: string | null
  title: string | null
  description: string | null
  url: string | null
  status: string
  created_at: string
}

export default function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  useEffect(() => {
    loadFindings()
  }, [])

  const loadFindings = async () => {
    try {
      const response = await api.get('/api/v1/findings')
      setFindings(response.data)
    } catch (error) {
      console.error('Failed to load findings:', error)
    } finally {
      setLoading(false)
    }
  }

  const filteredFindings = severityFilter === 'all'
    ? findings
    : findings.filter(f => f.severity === severityFilter)

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/10 text-red-500 border-red-500/20'
      case 'high': return 'bg-orange-500/10 text-orange-500 border-orange-500/20'
      case 'medium': return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'
      case 'low': return 'bg-blue-500/10 text-blue-500 border-blue-500/20'
      case 'info': return 'bg-gray-500/10 text-gray-500 border-gray-500/20'
      default: return 'bg-muted text-muted-foreground'
    }
  }

  if (loading) {
    return <div className="text-center py-12">Loading findings...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Findings</h1>
        <p className="text-muted-foreground mt-2">
          Vulnerabilities discovered across all scans
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>All Findings ({filteredFindings.length})</CardTitle>
              <CardDescription>Filter by severity</CardDescription>
            </div>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-4 py-2 rounded-md border border-input bg-background"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
        </CardHeader>
        <CardContent>
          {filteredFindings.length === 0 ? (
            <p className="text-center text-muted-foreground py-8">
              No findings yet. Run scans to discover vulnerabilities.
            </p>
          ) : (
            <div className="space-y-2">
              {filteredFindings.map((finding) => (
                <div
                  key={finding.id}
                  className="p-4 rounded-lg border border-border hover:bg-accent/50 transition-colors"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <span className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(finding.severity)}`}>
                          {finding.severity?.toUpperCase()}
                        </span>
                        <span className="text-sm font-medium">{finding.scanner}</span>
                      </div>
                      {finding.title && (
                        <div className="font-medium mb-1">{finding.title}</div>
                      )}
                      {finding.description && (
                        <div className="text-sm text-muted-foreground mb-2">
                          {finding.description}
                        </div>
                      )}
                      {finding.url && (
                        <div className="text-xs text-muted-foreground font-mono">
                          {finding.url}
                        </div>
                      )}
                      <div className="text-xs text-muted-foreground mt-2">
                        {new Date(finding.created_at).toLocaleString()}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
