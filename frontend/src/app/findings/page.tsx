'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { api } from '@/lib/api'
import { Search, AlertTriangle, ExternalLink, Filter, ArrowUpDown, CheckCircle2, AlertCircle } from 'lucide-react'
import { publicApi } from '@/lib/api'

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
  cve_id?: string
  cvss_score?: number
  created_at: string
}

export default function FindingsPage() {
  const router = useRouter()
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [scannerFilter, setScannerFilter] = useState<string>('all')
  const [sortBy, setSortBy] = useState<'date' | 'severity' | 'scanner'>('date')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')

  useEffect(() => {
    loadFindings()
  }, [])

  const loadFindings = async () => {
    try {
      const response = await publicApi.get('/api/v1/public/findings')
      setFindings(response.data)
    } catch (error) {
      console.error('Failed to load findings:', error)
    } finally {
      setLoading(false)
    }
  }

  const filteredFindings = findings.filter(finding => {
    const matchesSearch = !searchQuery ||
      (finding.title?.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (finding.description?.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (finding.scanner?.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (finding.category?.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (finding.cve_id?.toLowerCase().includes(searchQuery.toLowerCase()))

    const matchesSeverity = severityFilter === 'all' || finding.severity === severityFilter
    const matchesScanner = scannerFilter === 'all' || finding.scanner === scannerFilter

    return matchesSearch && matchesSeverity && matchesScanner
  })

  const sortedFindings = [...filteredFindings].sort((a, b) => {
    let comparison = 0

    if (sortBy === 'date') {
      comparison = new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
    } else if (sortBy === 'severity') {
      const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
      comparison = severityOrder[a.severity || 'info'] - severityOrder[b.severity || 'info']
    } else if (sortBy === 'scanner') {
      comparison = a.scanner.localeCompare(b.scanner)
    }

    return sortOrder === 'asc' ? comparison : -comparison
  })

  const getSeverityColor = (severity: string) => {
    const colors = {
      critical: 'bg-red-500/10 text-red-500 border-red-500/20',
      high: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
      medium: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
      low: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
      info: 'bg-gray-500/10 text-gray-500 border-gray-500/20'
    }
    return colors[severity as keyof typeof colors] || colors.info
  }

  const getStatusColor = (status: string) => {
    const colors = {
      new: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
      confirmed: 'bg-green-500/10 text-green-500 border-green-500/20',
      false_positive: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
      fixed: 'bg-blue-500/10 text-blue-500 border-blue-500/20'
    }
    return colors[status as keyof typeof colors] || colors.new
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
          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Search className="h-5 w-5 text-muted-foreground" />
                <Input
                  type="text"
                  placeholder="Search findings by title, description, scanner, category, or CVE..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-96"
                />
              </div>
              <div className="flex items-center gap-2">
                <Select value={sortBy} onValueChange={(value: any) => setSortBy(value)}>
                  <SelectTrigger className="w-[140px]">
                    <SelectValue placeholder="Sort by" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="date">Date</SelectItem>
                    <SelectItem value="severity">Severity</SelectItem>
                    <SelectItem value="scanner">Scanner</SelectItem>
                  </SelectContent>
                </Select>
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
                >
                  <ArrowUpDown className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="w-[150px]">
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severities</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                  <SelectItem value="info">Info</SelectItem>
                </SelectContent>
              </Select>

              <Select value={scannerFilter} onValueChange={setScannerFilter}>
                <SelectTrigger className="w-[150px]">
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue placeholder="Scanner" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Scanners</SelectItem>
                  <SelectItem value="waf">WAF</SelectItem>
                  <SelectItem value="xss">XSS</SelectItem>
                  <SelectItem value="sqli">SQLi</SelectItem>
                  <SelectItem value="ssrf">SSRF</SelectItem>
                  <SelectItem value="lfi">LFI</SelectItem>
                  <SelectItem value="cors">CORS</SelectItem>
                  <SelectItem value="sssti">SSTI</SelectItem>
                  <SelectItem value="graphql">GraphQL</SelectItem>
                  <SelectItem value="portscan">Port Scan</SelectItem>
                  <SelectItem value="fuzzer">Fuzzer</SelectItem>
                  <SelectItem value="tech">Tech</SelectItem>
                  <SelectItem value="jsanalysis">JS Analysis</SelectItem>
                  <SelectItem value="openredirect">Open Redirect</SelectItem>
                  <SelectItem value="hostheader">Host Header</SelectItem>
                  <SelectItem value="crlf">CRLF</SelectItem>
                  <SelectItem value="nuclei">Nuclei</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {sortedFindings.length === 0 ? (
            <div className="text-center text-muted-foreground py-12">
              <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No findings found. Try adjusting your filters or run a new scan.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {sortedFindings.map((finding) => (
                <Card
                  key={finding.id}
                  className="hover:shadow-md transition-all cursor-pointer"
                  onClick={() => router.push(`/findings/${finding.id}`)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-2 flex-wrap">
                          <span className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(finding.severity)}`}>
                            {finding.severity?.toUpperCase()}
                          </span>
                          <Badge variant="outline" className="text-xs">
                            {finding.scanner}
                          </Badge>
                          {finding.cve_id && (
                            <Badge variant="outline" className="text-xs">
                              CVE: {finding.cve_id}
                            </Badge>
                          )}
                          {finding.cvss_score && (
                            <Badge variant="outline" className="text-xs">
                              CVSS: {finding.cvss_score}
                            </Badge>
                          )}
                        </div>

                        {finding.title && (
                          <h3 className="font-semibold mb-1 truncate">{finding.title}</h3>
                        )}

                        {finding.description && (
                          <p className="text-sm text-muted-foreground mb-2 line-clamp-2">
                            {finding.description}
                          </p>
                        )}

                        {finding.url && (
                          <div className="flex items-center gap-2 mb-2">
                            <a
                              href={finding.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs text-blue-500 hover:underline truncate max-w-[300px]"
                              onClick={(e) => e.stopPropagation()}
                            >
                              {finding.url}
                            </a>
                            <ExternalLink className="h-3 w-3 text-muted-foreground" />
                          </div>
                        )}

                        <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                          {finding.category && (
                            <span>{finding.category}</span>
                          )}
                          {finding.status && (
                            <span className={`flex items-center gap-1`}>
                              {finding.status === 'confirmed' && <CheckCircle2 className="h-3 w-3" />}
                              {finding.status === 'false_positive' && <AlertCircle className="h-3 w-3" />}
                              {finding.status}
                            </span>
                          )}
                          <span>{new Date(finding.created_at).toLocaleDateString()}</span>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <div className="flex items-center justify-between text-sm text-muted-foreground">
        <p>{sortedFindings.length} finding{sortedFindings.length !== 1 ? 's' : ''} displayed</p>
      </div>
    </div>
  )
}
