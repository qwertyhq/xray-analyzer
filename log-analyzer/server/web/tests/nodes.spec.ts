import { test, expect } from '@playwright/test';

test.describe('Nodes Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/nodes');
  });

  test('displays nodes page heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Nodes' })).toBeVisible();
  });

  test('shows online nodes section', async ({ page }) => {
    await expect(page.getByText('Online Nodes')).toBeVisible();
  });

  test('displays nodes table with correct columns', async ({ page }) => {
    // Wait for table to load
    await page.waitForSelector('table');
    
    await expect(page.getByRole('columnheader', { name: 'Node ID' }).first()).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Status' }).first()).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Requests' }).first()).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Blacklist' }).first()).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Last Seen' }).first()).toBeVisible();
  });

  test('shows online status badges', async ({ page }) => {
    // Look for any online badge
    const onlineBadge = page.locator('text=Online').first();
    await expect(onlineBadge).toBeVisible();
  });

  test('can navigate back to dashboard', async ({ page }) => {
    await page.getByRole('link', { name: 'Dashboard' }).click();
    await expect(page).toHaveURL(/.*\/dashboard/);
  });
});

test.describe('Offline Nodes', () => {
  test('shows offline nodes section when offline nodes exist', async ({ page }) => {
    await page.goto('/nodes');
    
    // Check if offline section exists (may or may not be present)
    const offlineSection = page.getByText('Offline Nodes');
    const hasOffline = await offlineSection.isVisible().catch(() => false);
    
    if (hasOffline) {
      await expect(offlineSection).toBeVisible();
      // Offline nodes should have delete button
      await expect(page.getByRole('button', { name: /delete/i })).toBeVisible();
    }
  });
});
