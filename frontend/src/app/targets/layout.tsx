import AppLayout from '@/components/layout'

export default function TargetsLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return <AppLayout>{children}</AppLayout>
}