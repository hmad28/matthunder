'use client'

import { useEffect, useState } from 'react'
import { useRouter, useParams } from 'next/navigation'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { publicApi } from '@/lib/api'
import { ArrowLeft, Copy, ExternalLink, FileText, AlertTriangle, CheckCircle2, AlertCircle } from 'lucide-react'
import { toast } from 'sonner'

interface Finding {
  id: string
  scan_id: string
  scanner: string
  severity: string
  category?: string
  title?: string
  description?: string
  url?: string
  source_url?: string
  evidence?: string
  http_code?: number
  status: string
  cve_id?: string
  cvss_score?: number
  remediation?: string
  metadata_?: any
  created_at: string
}

export default function FindingDetailPage() {
  const router = useRouter()
  const params = useParams()
  const findingId = params.id as string
  const [finding, setFinding] = useState<Finding | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadFinding()
  }, [findingId])

  const loadFinding = async () => {
    try {
      const response = await publicApi.get(`/api/v1/public/findings/${findingId}`)
      setFinding(response.data)
    } catch (error) {
      console.error('Failed to load finding:', error)
      toast.error('Failed to load finding')
    } finally {
      setLoading(false)
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'confirmed': return <CheckCircle2 className="h-4 w-4 text-green-500" />
      case 'false_positive': return <AlertCircle className="h-4 w-4 text-yellow-500" />
      case 'fixed': return <CheckCircle2 className="h-4 w-4 text-blue-500" />
      default: return <AlertTriangle className="h-4 w-4 text-gray-500" />
    }
  }

  const getSeverityBadge = (severity: string) => {
    const colors = {
      critical: 'bg-red-500/10 text-red-500 border-red-500/20',
      high: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
      medium: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
      low: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
      info: 'bg-gray-500/10 text-gray-500 border-gray-500/20'
    }
    return (
      <Badge className={colors[severity as keyof typeof colors] || colors.info}>
        {severity?.toUpperCase()}
      </Badge>
    )
  }

  const copyToClipboard = (text: string | undefined) => {
    if (text) {
      navigator.clipboard.writeText(text)
      toast.success('Copied to clipboard')
    }
  }

  const getStepToReproduce = () => {
    if (!finding?.metadata_?.step_to_reproduce) return null
    return finding.metadata_.step_to_reproduce
  }

  const getAttackPath = () => {
    if (!finding?.metadata_?.attack_path) return null
    return finding.metadata_.attack_path
  }

  if (loading) {
    return <div className="text-center py-12">Loading finding...</div>
  }

  if (!finding) {
    return <div className="text-center py-12">Finding not found</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <Button
          variant="ghost"
          onClick={() => router.back()}
          className="mb-4"
        >
          <ArrowLeft className="h-4 w-4 mr-2" />
          Back to Findings
        </Button>
        <h1 className="text-3xl font-bold">Vulnerability Details</h1>
        <p className="text-muted-foreground mt-2">
          Detailed analysis of discovered vulnerability
        </p>
      </div>

      <div className="grid gap-6">
        <Card>
          <CardHeader>
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <h2 className="text-2xl font-semibold">{finding.title || 'Untitled Finding'}</h2>
                  {getSeverityBadge(finding.severity)}
                  {finding.status && (
                    <Badge className="bg-blue-500/10 text-blue-500 border-blue-500/20">
                      {finding.status}
                    </Badge>
                  )}
                </div>
                <div className="flex items-center gap-4 text-sm text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <AlertTriangle className="h-4 w-4" />
                    {finding.scanner}
                  </span>
                  {finding.category && (
                    <span>{finding.category}</span>
                  )}
                  {finding.cve_id && (
                    <span className="flex items-center gap-1">
                      <FileText className="h-4 w-4" />
                      CVE: {finding.cve_id}
                    </span>
                  )}
                  {finding.cvss_score && (
                    <span>CVSS: {finding.cvss_score}</span>
                  )}
                </div>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {finding.description && (
              <div>
                <h3 className="font-semibold mb-2">Description</h3>
                <p className="text-muted-foreground">{finding.description}</p>
              </div>
            )}

            {finding.url && (
              <div>
                <h3 className="font-semibold mb-2">Vulnerable URL</h3>
                <div className="flex items-center gap-2">
                  <a
                    href={finding.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-500 hover:underline"
                  >
                    {finding.url}
                  </a>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => copyToClipboard(finding.url)}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                  <ExternalLink className="h-4 w-4 text-muted-foreground" />
                </div>
              </div>
            )}

            {finding.source_url && (
              <div>
                <h3 className="font-semibold mb-2">Source URL</h3>
                <div className="flex items-center gap-2">
                  <a
                    href={finding.source_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-500 hover:underline"
                  >
                    {finding.source_url}
                  </a>
                  <ExternalLink className="h-4 w-4 text-muted-foreground" />
                </div>
              </div>
            )}

            {finding.http_code && (
              <div>
                <h3 className="font-semibold mb-2">HTTP Status Code</h3>
                <Badge variant="outline">{finding.http_code}</Badge>
              </div>
            )}

            {finding.remediation && (
              <div>
                <h3 className="font-semibold mb-2">Remediation</h3>
                <div className="bg-muted/50 p-4 rounded-lg">
                  <p className="text-muted-foreground whitespace-pre-wrap">{finding.remediation}</p>
                </div>
              </div>
            )}

            {finding.evidence && (
              <div>
                <h3 className="font-semibold mb-2">Evidence</h3>
                <div className="bg-muted/50 p-4 rounded-lg">
                  <pre className="text-sm text-muted-foreground whitespace-pre-wrap font-mono">{finding.evidence}</pre>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <Tabs defaultValue="reproduce" className="w-full">
          <TabsList>
            <TabsTrigger value="reproduce">Step to Reproduce</TabsTrigger>
            <TabsTrigger value="attack-path">Attack Path</TabsTrigger>
            <TabsTrigger value="metadata">Metadata</TabsTrigger>
          </TabsList>

          <TabsContent value="reproduce">
            <Card>
              <CardHeader>
                <CardTitle>Reproduction Steps</CardTitle>
                <CardDescription>
                  Step-by-step instructions to reproduce this vulnerability
                </CardDescription>
              </CardHeader>
              <CardContent>
                {getStepToReproduce() ? (
                  <ol className="list-decimal list-inside space-y-2 text-muted-foreground">
                    {getStepToReproduce().split('\n').map((step: string, idx: number) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ol>
                ) : (
                  <p className="text-muted-foreground">No reproduction steps available.</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="attack-path">
            <Card>
              <CardHeader>
                <CardTitle>Attack Path</CardTitle>
                <CardDescription>
                  Visual representation of the attack chain
                </CardDescription>
              </CardHeader>
              <CardContent>
                {getAttackPath() ? (
                  <div className="bg-muted/50 p-4 rounded-lg">
                    <pre className="text-sm whitespace-pre-wrap font-mono">{getAttackPath()}</pre>
                  </div>
                ) : (
                  <p className="text-muted-foreground">No attack path available.</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="metadata">
            <Card>
              <CardHeader>
                <CardTitle>Metadata</CardTitle>
                <CardDescription>
                  Additional technical details about this finding
                </CardDescription>
              </CardHeader>
              <CardContent>
                {finding.metadata_ && Object.keys(finding.metadata_).length > 0 ? (
                  <div className="space-y-3">
                    {Object.entries(finding.metadata_).map(([key, value]) => (
                      <div key={key}>
                        <h4 className="font-semibold text-sm capitalize">{key.replace(/_/g, ' ')}</h4>
                        <pre className="text-sm text-muted-foreground mt-1 whitespace-pre-wrap">
                          {typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}
                        </pre>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-muted-foreground">No metadata available.</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}