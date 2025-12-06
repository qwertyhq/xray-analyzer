import { test, expect } from '@playwright/test';

test.describe('Users Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/users');
  });

  test('displays users page heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Users' })).toBeVisible();
  });

  test('shows user statistics cards', async ({ page }) => {
    await expect(page.getByText('Total Users').first()).toBeVisible();
    await expect(page.getByText('Total Requests').first()).toBeVisible();
    await expect(page.getByText('Flagged Users')).toBeVisible();
    await expect(page.getByText('Blacklist Hits').first()).toBeVisible();
  });

  test('displays tabs for filtering', async ({ page }) => {
    await expect(page.getByRole('tab', { name: /All Users/ })).toBeVisible();
    await expect(page.getByRole('tab', { name: /Blacklist Only/ })).toBeVisible();
  });

  test('shows search input', async ({ page }) => {
    await expect(page.getByPlaceholder('Search by user or node...')).toBeVisible();
  });

  test('displays users table with correct columns', async ({ page }) => {
    await page.waitForSelector('table');
    
    await expect(page.getByRole('columnheader', { name: 'User' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Node' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Requests' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Blacklist Hits' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Destinations' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Last Seen' })).toBeVisible();
  });

  test('shows pagination controls', async ({ page }) => {
    await page.waitForSelector('text=Showing');
    
    await expect(page.getByText(/Showing \d+-\d+ of \d+/)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Previous' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Next' })).toBeVisible();
  });

  test('can switch to blacklist tab', async ({ page }) => {
    await page.getByRole('tab', { name: /Blacklist Only/ }).click();
    
    // Wait for tab to be selected
    await expect(page.getByRole('tab', { name: /Blacklist Only/ })).toHaveAttribute('aria-selected', 'true');
    
    // Blacklist tab should have additional column
    await expect(page.getByRole('columnheader', { name: 'Last Blocked Domain' })).toBeVisible();
  });

  test('can search users', async ({ page }) => {
    const searchInput = page.getByPlaceholder('Search by user or node...');
    await searchInput.fill('HQVPN');
    
    // Wait for filtering
    await page.waitForTimeout(500);
    
    // Should show filtered results (or no results if search is instant)
    const table = page.locator('table');
    await expect(table).toBeVisible();
  });
});

test.describe('User Details Page', () => {
  test('can navigate to user details', async ({ page }) => {
    await page.goto('/users');
    
    // Wait for table to load
    await page.waitForSelector('table tbody tr');
    
    // Click on first user link
    const firstUserLink = page.locator('table tbody tr').first().getByRole('link');
    const userName = await firstUserLink.textContent();
    await firstUserLink.click();
    
    // Should navigate to user details page
    await expect(page).toHaveURL(/.*\/users\/.+/);
    
    // Should show user name in heading
    if (userName) {
      await expect(page.getByRole('heading', { name: userName.trim() })).toBeVisible();
    }
  });

  test('displays user statistics', async ({ page }) => {
    await page.goto('/users');
    await page.waitForSelector('table tbody tr');
    
    await page.locator('table tbody tr').first().getByRole('link').click();
    
    await expect(page.getByText('Total Requests').first()).toBeVisible();
    await expect(page.getByText('Blacklist Hits').first()).toBeVisible();
    await expect(page.getByText('Active Nodes')).toBeVisible();
  });

  test('shows activity by node table', async ({ page }) => {
    await page.goto('/users');
    await page.waitForSelector('table tbody tr');
    
    await page.locator('table tbody tr').first().getByRole('link').click();
    
    await expect(page.getByText('Activity by Node')).toBeVisible();
  });

  test('has back button to users list', async ({ page }) => {
    await page.goto('/users');
    await page.waitForSelector('table tbody tr');
    
    await page.locator('table tbody tr').first().getByRole('link').click();
    
    // Find and click back button
    await page.locator('a[href="/users"] button').click();
    
    await expect(page).toHaveURL(/.*\/users$/);
  });
});

test.describe('Blacklist User Details', () => {
  test('shows blacklist matches for flagged user', async ({ page }) => {
    await page.goto('/users');
    
    // Switch to blacklist tab
    await page.getByRole('tab', { name: /Blacklist Only/ }).click();
    
    // Wait for tab content
    await page.waitForSelector('table tbody tr');
    
    // Check if there are any blacklisted users
    const rows = page.locator('table tbody tr');
    const count = await rows.count();
    
    if (count > 0) {
      // Click on first blacklisted user
      await rows.first().getByRole('link').click();
      
      await expect(page).toHaveURL(/.*\/users\/.+/);
      
      // Should show blacklist matches table
      await expect(page.getByText('Recent Blacklist Matches')).toBeVisible();
    }
  });
});
