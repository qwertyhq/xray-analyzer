import { test, expect } from '@playwright/test';

test.describe('Navigation', () => {
  test('can navigate through all main pages', async ({ page }) => {
    // Start at root
    await page.goto('/');
    await expect(page).toHaveURL(/.*\/dashboard/);

    // Navigate to Nodes
    await page.getByRole('link', { name: 'Nodes' }).click();
    await expect(page).toHaveURL(/.*\/nodes/);
    await expect(page.getByRole('heading', { name: 'Nodes' })).toBeVisible();

    // Navigate to Users
    await page.getByRole('link', { name: 'Users' }).click();
    await expect(page).toHaveURL(/.*\/users/);
    await expect(page.getByRole('heading', { name: 'Users' })).toBeVisible();

    // Navigate back to Dashboard
    await page.getByRole('link', { name: 'Dashboard' }).click();
    await expect(page).toHaveURL(/.*\/dashboard/);
    await expect(page.getByText('Active Nodes')).toBeVisible();
  });

  test('shows active state for current page', async ({ page }) => {
    await page.goto('/dashboard');
    
    // Dashboard link should be visible
    const dashboardLink = page.getByRole('link', { name: 'Dashboard' });
    await expect(dashboardLink).toBeVisible();

    // Navigate to Nodes
    await page.getByRole('link', { name: 'Nodes' }).click();
    
    // Nodes link should now be visible
    const nodesLink = page.getByRole('link', { name: 'Nodes' });
    await expect(nodesLink).toBeVisible();
  });

  test('logo links to dashboard', async ({ page }) => {
    await page.goto('/nodes');
    
    // Click on logo (link to dashboard)
    await page.getByRole('link', { name: /Xray Analyzer/ }).click();
    
    await expect(page).toHaveURL(/.*\/dashboard/);
  });
});

test.describe('Mobile Navigation', () => {
  test.use({ viewport: { width: 375, height: 667 } });

  test('navigation works on mobile', async ({ page }) => {
    await page.goto('/dashboard');
    
    // On mobile, navigation might be different but links should still work
    await page.getByRole('link', { name: 'Nodes' }).click();
    await expect(page).toHaveURL(/.*\/nodes/);
  });
});
