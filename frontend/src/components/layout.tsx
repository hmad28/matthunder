'use client'

import Link from 'next/link'
import {
  LayoutDashboard,
  Target,
  Scan,
  AlertTriangle,
  FileText,
  Workflow,
  Terminal,
  Bot,
  Settings
} from 'lucide-react'

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Targets', href: '/targets', icon: Target },
  { name: 'Scans', href: '/scans', icon: Scan },
  { name: 'Findings', href: '/findings', icon: AlertTriangle },
  { name: 'Reports', href: '/reports', icon: FileText },
  { name: 'Pipeline', href: '/pipeline', icon: Workflow },
  { name: 'Scanners', href: '/scanners', icon: Terminal },
  { name: 'AI Analysis', href: '/ai', icon: Bot },
  { separator: true },
  { name: 'Reasoning', href: '/reasoning', icon: Workflow },
  { name: 'Swarm', href: '/swarm', icon: Terminal },
  { name: 'Memory', href: '/memory', icon: FileText },
  { separator: true },
  { name: 'Settings', href: '/settings', icon: Settings },
]

export default function AppLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <div className="hidden md:flex md:w-64 md:flex-col">
        <div className="flex flex-col flex-grow border-r border-border bg-card overflow-y-auto">
          <div className="flex items-center h-16 px-6 border-b border-border">
            <h1 className="text-xl font-bold text-primary">matthunder</h1>
          </div>
          <div className="flex-grow flex flex-col pt-5 pb-4">
            <nav className="flex-1 px-4 space-y-1">
              {navigation.map((item: any) => (
                item.separator ? (
                  <div key={Math.random()} className="border-t border-border my-2" />
                ) : (
                  <Link
                    key={item.name}
                    href={item.href}
                    className="group flex items-center px-3 py-2 text-sm font-medium rounded-md hover:bg-accent hover:text-accent-foreground transition-colors"
                  >
                    <item.icon className="mr-3 h-5 w-5" />
                    {item.name}
                  </Link>
                )
              ))}
            </nav>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="flex flex-col flex-1 overflow-hidden">
        <main className="flex-1 relative overflow-y-auto focus:outline-none">
          <div className="py-6">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 md:px-8">
              {children}
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}