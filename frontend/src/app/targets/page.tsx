'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Plus, Trash2 } from 'lucide-react'
import { publicApi, api } from '@/lib/api'

interface Target {
  id: string
  domain: string
  notes: string | null
  created_at: string
}

export default function TargetsPage() {
  const [targets, setTargets] = useState<Target[]>([])
  const [newDomain, setNewDomain] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadTargets()
  }, [])

  const loadTargets = async () => {
    try {
      const response = await publicApi.get('/api/v1/public/targets')
      setTargets(response.data)
    } catch (error) {
      console.error('Failed to load targets:', error)
    } finally {
      setLoading(false)
    }
  }

  const addTarget = async () => {
    if (!newDomain.trim()) return

    try {
      await api.post('/api/v1/targets', { domain: newDomain.trim() })
      setNewDomain('')
      loadTargets()
    } catch (error) {
      console.error('Failed to add target:', error)
    }
  }

  const deleteTarget = async (id: string) => {
    if (!confirm('Are you sure you want to delete this target?')) return

    try {
      await api.delete(`/api/v1/targets/${id}`)
      loadTargets()
    } catch (error) {
      console.error('Failed to delete target:', error)
    }
  }

  if (loading) {
    return <div className="text-center py-12">Loading targets...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Targets</h1>
        <p className="text-muted-foreground mt-2">
          Manage your bug bounty targets
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Add New Target</CardTitle>
          <CardDescription>Add a domain to scan</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2">
            <input
              type="text"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="example.com"
              className="flex-1 px-4 py-2 rounded-md border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
              onKeyPress={(e) => e.key === 'Enter' && addTarget()}
            />
            <Button onClick={addTarget}>
              <Plus className="h-4 w-4 mr-2" />
              Add Target
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>All Targets ({targets.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {targets.length === 0 ? (
            <p className="text-center text-muted-foreground py-8">
              No targets yet. Add your first target above.
            </p>
          ) : (
            <div className="space-y-2">
              {targets.map((target) => (
                <div
                  key={target.id}
                  className="p-4 rounded-lg border border-border hover:bg-accent/50 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="font-medium">{target.domain}</div>
                      {target.notes && (
                        <div className="text-sm text-muted-foreground mt-1">
                          {target.notes}
                        </div>
                      )}
                      <div className="text-xs text-muted-foreground mt-1">
                        Added {new Date(target.created_at).toLocaleDateString()}
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => deleteTarget(target.id)}
                    >
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
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