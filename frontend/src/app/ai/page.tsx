'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { api } from '@/lib/api'

export default function AIPage() {
  const [prompt, setPrompt] = useState('')
  const [provider, setProvider] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState<any>(null)

  const analyze = async () => {
    if (!prompt.trim()) return
    
    setAnalyzing(true)
    setResult(null)
    
    try {
      const response = await api.post('/api/v1/ai/analyze', {
        prompt: prompt,
        provider: provider || undefined
      })
      setResult(response.data)
    } catch (error) {
      console.error('Failed to analyze:', error)
      alert('Failed to analyze')
    } finally {
      setAnalyzing(false)
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">AI Analysis</h1>
        <p className="text-muted-foreground mt-2">
          AI-powered vulnerability analysis and insights
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Analyze with AI</CardTitle>
          <CardDescription>Ask questions about your findings or get remediation advice</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium">AI Provider</label>
              <select
                value={provider}
                onChange={(e) => setProvider(e.target.value)}
                className="w-full mt-1 px-4 py-2 rounded-md border border-input bg-background"
              >
                <option value="">Auto-detect</option>
                <option value="openai">OpenAI</option>
                <option value="anthropic">Anthropic</option>
                <option value="gemini">Google Gemini</option>
                <option value="openrouter">OpenRouter</option>
              </select>
            </div>

            <div>
              <label className="text-sm font-medium">Prompt</label>
              <textarea
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
                placeholder="Ask a question about your findings, request remediation advice, or analyze vulnerabilities..."
                rows={6}
                className="w-full mt-1 px-4 py-2 rounded-md border border-input bg-background resize-none"
              />
            </div>

            <Button
              onClick={analyze}
              disabled={!prompt.trim() || analyzing}
              className="w-full"
            >
              {analyzing ? 'Analyzing...' : 'Analyze'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {result && (
        <Card>
          <CardHeader>
            <CardTitle>Analysis Result</CardTitle>
            <CardDescription>
              Provider: {result.provider} • Model: {result.model}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="prose prose-invert max-w-none">
              <pre className="whitespace-pre-wrap text-sm">
                {result.response.content || JSON.stringify(result.response, null, 2)}
              </pre>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
