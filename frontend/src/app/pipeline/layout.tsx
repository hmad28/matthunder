import AppLayout from '@/components/layout'

export default function PipelineLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return <AppLayout>{children}</AppLayout>
}