'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { api } from '@/lib/api'

export default function SettingsPage() {
  const [config, setConfig] = useState<any>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadConfig()
  }, [])

  const loadConfig = async () => {
    try {
      const response = await api.get('/api/v1/config')
      setConfig(response.data)
    } catch (error) {
      console.error('Failed to load config:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <div className="text-center py-12">Loading settings...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-muted-foreground mt-2">
          Application configuration and status
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Application Info</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between py-2 border-b border-border">
              <span className="text-muted-foreground">App Name</span>
              <span className="font-medium">{config?.app_name}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <span className="text-muted-foreground">Version</span>
              <span className="font-medium">{config?.version}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <span className="text-muted-foreground">Debug Mode</span>
              <span className="font-medium">{config?.debug ? 'Enabled' : 'Disabled'}</span>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Scanner Configuration</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between py-2 border-b border-border">
              <span className="text-muted-foreground">Katana Limit</span>
              <span className="font-medium">{config?.katana_limit}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <span className="text-muted-foreground">Default Speed</span>
              <span className="font-medium">{config?.scan_speed}</span>
            </div>
            <div className="flex justify-between py-2 border-b border-border">
              <span className="text-muted-foreground">Scan Timeout</span>
              <span className="font-medium">{config?.scan_timeout}s</span>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>AI Providers</CardTitle>
          <CardDescription>Configured AI providers for analysis</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {Object.entries(config?.ai_providers || {}).map(([provider, configured]) => (
              <div key={provider} className="flex justify-between py-2 border-b border-border">
                <span className="text-muted-foreground capitalize">{provider}</span>
                <span className={`font-medium ${configured ? 'text-green-500' : 'text-red-500'}`}>
                  {configured ? 'Configured' : 'Not Configured'}
                </span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Integrations</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            <div className="flex justify-between py-2 border-b border-border">
              <span className="text-muted-foreground">Acunetix</span>
              <span className={`font-medium ${config?.acunetix_configured ? 'text-green-500' : 'text-red-500'}`}>
                {config?.acunetix_configured ? 'Configured' : 'Not Configured'}
              </span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
