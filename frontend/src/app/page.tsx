import type { Metadata } from 'next'
import Link from 'next/link'
import { Target, Scan, AlertTriangle, Workflow } from 'lucide-react'
import { Button } from '@/components/ui/button'

export const metadata: Metadata = {
  title: 'matthunder - AI-Powered Bug Hunting Platform',
  description: 'Advanced bug bounty reconnaissance and vulnerability scanning automation platform',
}

export default function Home() {
  return (
    <div className="min-h-screen bg-background">
      <div className="flex flex-col items-center justify-center min-h-screen px-4 py-12">
        <div className="text-center space-y-8">
          <div className="flex items-center justify-center gap-3">
            <h1 className="text-6xl font-bold bg-gradient-to-r from-primary to-blue-500 bg-clip-text text-transparent">
              ⚡ matthunder
            </h1>
          </div>
          <p className="text-xl text-muted-foreground max-w-2xl">
            AI-Powered Bug Hunting & Penetration Testing Platform
          </p>
          <div className="flex gap-4 justify-center pt-4">
            <Link
              href="/dashboard"
              className="px-8 py-4 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors text-lg font-medium"
            >
              Go to Dashboard
            </Link>
            <Link
              href="/targets"
              className="px-8 py-4 border-2 border-border rounded-lg hover:bg-accent transition-colors text-lg font-medium"
            >
              Add Target
            </Link>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl mx-auto pt-12">
            <div className="p-6 rounded-lg border border-border bg-card">
              <Target className="h-10 w-10 text-primary mx-auto mb-3" />
              <h3 className="font-semibold mb-2">Smart Targets</h3>
              <p className="text-sm text-muted-foreground">
                Manage bug bounty targets with scope enforcement
              </p>
            </div>
            <div className="p-6 rounded-lg border border-border bg-card">
              <Scan className="h-10 w-10 text-primary mx-auto mb-3" />
              <h3 className="font-semibold mb-2">Automated Scans</h3>
              <p className="text-sm text-muted-foreground">
                20+ scanners with AI-powered analysis
              </p>
            </div>
            <div className="p-6 rounded-lg border border-border bg-card">
              <AlertTriangle className="h-10 w-10 text-primary mx-auto mb-3" />
              <h3 className="font-semibold mb-2">Detailed Reports</h3>
              <p className="text-sm text-muted-foreground">
                Step-to-reproduce and remediation guides
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}