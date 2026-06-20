import { expect, test } from '@playwright/test'

test('authorized normal hunting flow starts from the web UI', async ({ page }) => {
  const suffix = Date.now()
  const username = `qa_${suffix}`
  const password = 'Passw0rd!qa'
  const target = `qa-${suffix}.example.com`

  const consoleErrors: string[] = []
  page.on('console', (message) => {
    if (message.type() === 'error') {
      consoleErrors.push(message.text())
    }
  })

  await page.goto('/login')
  await page.getByRole('button', { name: 'Register' }).click()
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Email').fill(`${username}@example.com`)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Create account' }).click()

  await expect(page).toHaveURL(/\/dashboard/)
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()

  await page.goto('/targets')
  await page.getByPlaceholder('example.com').fill(target)
  await page.getByRole('button', { name: 'Add Target' }).click()
  await expect(page.getByText(target)).toBeVisible()

  await page.goto('/scans')
  await page.getByLabel('Target').selectOption({ label: target })
  await page.getByLabel('Scan Type').selectOption('light')
  await page.getByRole('button', { name: 'Start Scan' }).click()

  const scanRow = page.getByTestId('scan-history-row').first()
  await expect(scanRow).toContainText('light')
  await expect(scanRow).toContainText(/queued|running|completed/)
  expect(consoleErrors).toEqual([])
})
