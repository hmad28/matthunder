import AppLayout from '@/components/layout'

export default function ScansLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return <AppLayout>{children}</AppLayout>
}