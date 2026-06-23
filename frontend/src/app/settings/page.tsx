'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { publicApi } from '@/lib/api'
import { Save, RefreshCw, Eye, EyeOff, Globe, Key, Bot, Wifi, WifiOff } from 'lucide-react'
import { toast } from 'sonner'

export default function SettingsPage() {
  const [baseUrl, setBaseUrl] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [model, setModel] = useState('')
  const [configured, setConfigured] = useState(false)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [showKey, setShowKey] = useState(false)
  const [testResult, setTestResult] = useState<'idle' | 'success' | 'fail'>('idle')

  useEffect(() => {
    loadConfig()
  }, [])

  const loadConfig = async () => {
    try {
      const res = await publicApi.get('/api/v1/config')
      const providers = res.data?.ai_providers || {}
      const custom = providers.custom || {}
      
      setBaseUrl(custom.base_url || '')
      setModel(custom.model || '')
      setConfigured(custom.configured || false)
    } catch (e) {
      console.error('Failed to load config:', e)
    } finally {
      setLoading(false)
    }
  }

  const saveConfig = async () => {
    if (!baseUrl || !model) {
      toast.error('Base URL and Model are required')
      return
    }
    
    setSaving(true)
    try {
      await publicApi.post('/api/v1/config/update', {
        providers: {
          custom: {
            base_url: baseUrl,
            api_key: apiKey,
            model: model
          }
        }
      })
      toast.success('Configuration saved! Restart server to apply.')
      setConfigured(true)
    } catch (e: any) {
      toast.error('Failed to save: ' + (e?.response?.data?.detail || 'Unknown error'))
    } finally {
      setSaving(false)
    }
  }

  const testConnection = async () => {
    if (!baseUrl) return
    
    setTesting(true)
    setTestResult('idle')
    try {
      await publicApi.post('/api/v1/config/test', {
        base_url: baseUrl,
        api_key: apiKey,
        model: model || 'gpt-4o-mini'
      })
      setTestResult('success')
      toast.success('Connection successful!')
    } catch (e) {
      setTestResult('fail')
      toast.error('Connection failed')
    } finally {
      setTesting(false)
    }
  }

  if (loading) {
    return <div className="text-center py-12">Loading...</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-muted-foreground mt-2">Configure AI provider - BYOK (Bring Your Own Key)</p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Bot className="h-6 w-6 text-primary" />
              <div>
                <CardTitle>AI Provider</CardTitle>
                <CardDescription>Enter your OpenAI-compatible API endpoint</CardDescription>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {configured ? (
                <Badge className="bg-green-500/10 text-green-500 flex items-center gap-1">
                  <Wifi className="h-3 w-3" /> Configured
                </Badge>
              ) : (
                <Badge className="bg-red-500/10 text-red-500 flex items-center gap-1">
                  <WifiOff className="h-3 w-3" /> Not Configured
                </Badge>
              )}
              <Button onClick={saveConfig} disabled={saving}>
                {saving ? <><RefreshCw className="h-4 w-4 mr-2 animate-spin" /> Saving...</> : <><Save className="h-4 w-4 mr-2" /> Save</>}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-5">
          <div>
            <label className="text-sm font-medium mb-1.5 block">Base URL</label>
            <div className="flex gap-2">
              <Globe className="h-4 w-4 mt-3 text-muted-foreground shrink-0" />
              <Input
                placeholder="https://api.openai.com/v1 or http://localhost:11434/v1"
                value={baseUrl}
                onChange={e => setBaseUrl(e.target.value)}
              />
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Supports any OpenAI-compatible API (OpenAI, Anthropic, Ollama, vLLM, LocalAI, etc.)
            </p>
          </div>

          <div>
            <label className="text-sm font-medium mb-1.5 block">API Key</label>
            <div className="relative">
              <Key className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                type={showKey ? 'text' : 'password'}
                placeholder="sk-... or leave empty for local models"
                value={apiKey}
                onChange={e => setApiKey(e.target.value)}
                className="pl-10 pr-10"
              />
              <button
                type="button"
                onClick={() => setShowKey(!showKey)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              >
                {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Optional - some local models don't need an API key
            </p>
          </div>

          <div>
            <label className="text-sm font-medium mb-1.5 block">Model</label>
            <Input
              placeholder="gpt-4o-mini, claude-3-5-haiku, gemma2:2b, etc."
              value={model}
              onChange={e => setModel(e.target.value)}
            />
            <p className="text-xs text-muted-foreground mt-1">
              Model name supported by your provider
            </p>
          </div>

          <div className="flex gap-3 pt-2">
            <Button variant="outline" onClick={testConnection} disabled={testing || !baseUrl}>
              {testing ? <><RefreshCw className="h-4 w-4 mr-2 animate-spin" /> Testing...</> : <>Test Connection</>}
            </Button>
            {testResult === 'success' && (
              <Badge className="bg-green-500/10 text-green-500">Connection OK</Badge>
            )}
            {testResult === 'fail' && (
              <Badge className="bg-red-500/10 text-red-500">Connection Failed</Badge>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Compatible Providers</CardTitle>
          <CardDescription>Works with any OpenAI-compatible API</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-3">
            <div className="p-3 rounded-lg border border-border">
              <p className="font-medium">OpenAI</p>
              <p className="text-xs text-muted-foreground mt-1">api.openai.com/v1</p>
            </div>
            <div className="p-3 rounded-lg border border-border">
              <p className="font-medium">Anthropic</p>
              <p className="text-xs text-muted-foreground mt-1">api.anthropic.com/v1</p>
            </div>
            <div className="p-3 rounded-lg border border-border">
              <p className="font-medium">OpenRouter</p>
              <p className="text-xs text-muted-foreground mt-1">openrouter.ai/api/v1</p>
            </div>
            <div className="p-3 rounded-lg border border-border">
              <p className="font-medium">Ollama</p>
              <p className="text-xs text-muted-foreground mt-1">localhost:11434/v1</p>
            </div>
            <div className="p-3 rounded-lg border border-border">
              <p className="font-medium">vLLM</p>
              <p className="text-xs text-muted-foreground mt-1">localhost:8000/v1</p>
            </div>
            <div className="p-3 rounded-lg border border-border">
              <p className="font-medium">LocalAI</p>
              <p className="text-xs text-muted-foreground mt-1">localhost:8080/v1</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}