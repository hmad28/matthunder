import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import { ToastProvider } from '@/lib/toast-context'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'matthunder - AI-Powered Bug Hunting Platform',
  description: 'Advanced bug bounty reconnaissance and vulnerability scanning automation platform',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className={inter.className}>
        <ToastProvider>
          <div className="min-h-screen bg-background">
            {children}
          </div>
        </ToastProvider>
      </body>
    </html>
  )
}