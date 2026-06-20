export default function Home() {
  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="text-center space-y-6">
        <h1 className="text-6xl font-bold">⚡ matthunder</h1>
        <p className="text-xl text-muted-foreground">
          AI-Powered Bug Hunting & Penetration Testing Platform
        </p>
        <div className="flex gap-4 justify-center">
          <a
            href="/dashboard"
            className="px-6 py-3 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors"
          >
            Go to Dashboard
          </a>
          <a
            href="/docs"
            className="px-6 py-3 border border-border rounded-md hover:bg-accent transition-colors"
          >
            API Documentation
          </a>
        </div>
      </div>
    </div>
  )
}
