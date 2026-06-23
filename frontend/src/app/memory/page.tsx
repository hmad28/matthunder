'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { publicApi } from '@/lib/api'
import { 
  Database, FileText, RefreshCw, Search, 
  Clock, AlertTriangle, Target, Layers 
} from 'lucide-react'

interface ContextEntry {
  timestamp: string
  target_id: string
  scan_id: string
  context_type: string
  content: Record<string, any>
}

export default function MemoryPage() {
  const [entries, setEntries] = useState<ContextEntry[]>([])
  const [filter, setFilter] = useState('all')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadEntries()
  }, [])

  const loadEntries = async () => {
    try {
      const res = await publicApi.get('/api/v1/memory/entries')
      setEntries(res.data.entries || [])
    } catch (e) {
      console.error('Failed to load memory:', e)
      setEntries([])
    } finally {
      setLoading(false)
    }
  }

  const filteredEntries = filter === 'all' 
    ? entries 
    : entries.filter(e => e.context_type === filter)

  const getTypeBadge = (type: string) => {
    const colors: Record<string, string> = {
      target_metadata: 'bg-blue-500/10 text-blue-500',
      reconnaissance_map: 'bg-green-500/10 text-green-500',
      vulnerability_journal: 'bg-red-500/10 text-red-500',
      learning_patterns: 'bg-purple-500/10 text-purple-500',
      session_state: 'bg-yellow-500/10 text-yellow-500'
    }
    return (
      <Badge className={colors[type] || 'bg-gray-500/10 text-gray-500'}>
        {type.replace(/_/g, ' ')}
      </Badge>
    )
  }

  if (loading) return <div className="text-center py-12">Loading memory context...</div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Memory Context</h1>
          <p className="text-muted-foreground mt-2">
            Persistent AI memory and cross-target pattern learning
          </p>
        </div>
        <Button variant="outline" onClick={loadEntries}>
          <RefreshCw className="h-4 w-4 mr-2" /> Refresh
        </Button>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Context Entries ({entries.length})</CardTitle>
              <CardDescription>Filter by context type</CardDescription>
            </div>
            <div className="flex gap-2">
              {['all', 'target_metadata', 'reconnaissance_map', 'vulnerability_journal', 'learning_patterns', 'session_state'].map(type => (
                <Button
                  key={type}
                  variant={filter === type ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setFilter(type)}
                >
                  {type === 'all' ? 'All' : type.replace(/_/g, ' ')}
                </Button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {filteredEntries.length === 0 ? (
            <div className="text-center py-12 text-muted-foreground">
              <Database className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No memory entries found. Run a scan to generate context.</p>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredEntries.slice(0, 50).map((entry, idx) => (
                <Card key={idx} className="hover:shadow-md transition-all">
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        {getTypeBadge(entry.context_type)}
                        <span className="text-sm text-muted-foreground">
                          <Clock className="h-3 w-3 inline mr-1" />
                          {new Date(entry.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <Target className="h-3 w-3" />
                        {entry.target_id}
                      </div>
                    </div>
                    <div className="bg-muted/30 p-3 rounded-lg">
                      <pre className="text-xs font-mono text-muted-foreground overflow-x-auto max-h-32 whitespace-pre-wrap">
                        {JSON.stringify(entry.content, null, 2).slice(0, 500)}
                        {JSON.stringify(entry.content).length > 500 && '...'}
                      </pre>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}