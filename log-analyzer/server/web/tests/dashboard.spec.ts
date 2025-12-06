import { test, expect } from '@playwright/test';

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('redirects to dashboard', async ({ page }) => {
    await expect(page).toHaveURL(/.*\/dashboard/);
  });

  test('displays page title', async ({ page }) => {
    await expect(page).toHaveTitle(/Xray Log Analyzer/);
  });

  test('shows navigation links', async ({ page }) => {
    await expect(page.getByRole('link', { name: 'Dashboard' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Nodes' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Users' })).toBeVisible();
  });

  test('displays stats cards', async ({ page }) => {
    // Wait for stats to load
    await page.waitForSelector('text=Total Requests');
    
    await expect(page.getByText('Total Requests').first()).toBeVisible();
    await expect(page.getByText('Blacklist').first()).toBeVisible();
    await expect(page.getByText('Total Users').first()).toBeVisible();
  });

  test('displays activity chart section', async ({ page }) => {
    // Check that chart card title exists (Last 24 Hours or similar)
    await expect(page.getByText(/Last \d+ Hours?|Hourly Activity|Activity/i).first()).toBeVisible();
  });

  test('displays active nodes table', async ({ page }) => {
    await expect(page.getByText('Active Nodes')).toBeVisible();
    // Check table headers
    await expect(page.getByRole('columnheader', { name: 'Node ID' }).first()).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Status' })).toBeVisible();
  });

  test('displays blacklist alerts table', async ({ page }) => {
    await expect(page.getByText('Blacklist Alerts')).toBeVisible();
  });
});
